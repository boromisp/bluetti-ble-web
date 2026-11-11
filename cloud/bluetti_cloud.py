#!/usr/bin/env python3
"""Decode what a Bluetti power station sends to Bluetti's IoT cloud.

The station keeps a plain (unencrypted) MQTT 3.1.1 connection to
iot*.bluettipower.com:18760 and publishes to ``PUB/<model>/<serial>``.
Each publish payload starts with a 10-byte header:

    01 f8  KK  AA AA  ..  XX XX  00 00
    |      |   |      |   |---------- 14ed / 00ed (station), 0000 (cloud)
    |      |   |------------------------- dump: sequence no. / read: start register
    |      |----------------------------- kind: 01 = register dump (byte 3 counts
    |                                     dumps), 02 = status text,
    |                                     0f = read request/response
    |------------------------------------ magic

- Kind 01: the station's unsolicited dump, every 40-50 s, each publish a
  Modbus RTU "write multiple registers" frame (01 10 <start> <qty> <n>
  <data> <crc16-le>) covering one block of the BLE register map.
- Kind 0f: while the app is open the cloud polls by publishing a Modbus read
  (01 03 <start> <qty> <crc>) to SUB/<model>/<serial>; the station answers
  with a read response (01 03 <n> <data> <crc>) whose start register is in
  header bytes 3-4.
- Kind 02: a quoted status string such as
  "ac_sw=1,dc_sw=1,pv_sw=0,grid_sw=1,soc=94".

Usage:
    bluetti_cloud.py capture.pcap           decoded values after each dump
    bluetti_cloud.py --raw capture.pcap     also every register block

Standard library only. The register map below comes from Patrick762's
bluetti-bt-lib (MIT), devices/el30v2.py and base_devices/base_device_v2.py.
"""
from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field

MAGIC = b"\x01\xf8"
HEADER_LEN = 10


# ---------- Modbus ----------

def crc16(buf: bytes) -> int:
    crc = 0xFFFF
    for b in buf:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


@dataclass
class RegisterBlock:
    start: int
    words: tuple[int, ...]


@dataclass
class StatusText:
    fields: dict[str, str]


class DecodeError(ValueError):
    pass


def parse_payload(payload: bytes) -> RegisterBlock | StatusText:
    """Parse one PUB/<model>/<serial> payload."""
    if len(payload) < HEADER_LEN + 2 or payload[:2] != MAGIC:
        raise DecodeError(f"not a Bluetti payload: {payload[:4].hex()}")
    kind = payload[2]
    body = payload[HEADER_LEN:]
    if kind == 0x01:
        return _parse_modbus_write(body)
    if kind == 0x0F:
        start = struct.unpack(">H", payload[3:5])[0]
        return _parse_modbus_read_response(start, body)
    if kind == 0x02:
        q1 = body.find(b'"')
        q2 = body.find(b'"', q1 + 1)
        if q1 < 0 or q2 < 0:
            raise DecodeError("status text without quotes")
        text = body[q1 + 1:q2].decode("ascii", "replace")
        fields = dict(p.split("=", 1) for p in text.split(",") if "=" in p)
        return StatusText(fields)
    raise DecodeError(f"unknown message type {payload[2:4].hex()}")


def _parse_modbus_write(frame: bytes) -> RegisterBlock:
    if len(frame) < 9 or frame[0] != 0x01 or frame[1] != 0x10:
        raise DecodeError(f"not a Modbus write-multiple frame: {frame[:2].hex()}")
    start, qty, nbytes = struct.unpack(">HHB", frame[2:7])
    end = 7 + nbytes
    if nbytes != 2 * qty or len(frame) < end + 2:
        raise DecodeError(f"bad frame length: qty={qty} bytes={nbytes} have={len(frame)}")
    got = frame[end] | (frame[end + 1] << 8)
    if crc16(frame[:end]) != got:
        raise DecodeError(f"Modbus CRC mismatch in block at {start}")
    return RegisterBlock(start, struct.unpack(f">{qty}H", frame[7:end]))


def _parse_modbus_read_response(start: int, frame: bytes) -> RegisterBlock:
    if len(frame) < 5 or frame[0] != 0x01 or frame[1] != 0x03:
        raise DecodeError(f"not a Modbus read response: {frame[:2].hex()}")
    nbytes = frame[2]
    end = 3 + nbytes
    if nbytes % 2 or len(frame) < end + 2:
        raise DecodeError(f"bad read response length: bytes={nbytes} have={len(frame)}")
    got = frame[end] | (frame[end + 1] << 8)
    if crc16(frame[:end]) != got:
        raise DecodeError(f"Modbus CRC mismatch in read response at {start}")
    return RegisterBlock(start, struct.unpack(f">{nbytes // 2}H", frame[3:end]))


# ---------- register map (EL30V2) ----------

def _u(scale: float = 1):
    return lambda w: w[0] * scale if scale != 1 else w[0]


def _bool(w):
    return {0: False, 1: True}.get(w[0])


def _swapped_string(w):
    raw = b"".join(struct.pack("<H", x) for x in w)
    return raw.rstrip(b"\0").decode("ascii", "replace")


def _serial(w):
    return w[0] + (w[1] << 16) + (w[2] << 32) + (w[3] << 48)


# name: (address, size, decoder, unit)
EL30V2_FIELDS: dict[str, tuple[int, int, object, str | None]] = {
    "device_type":        (110, 6, _swapped_string, None),
    "device_sn":          (116, 4, _serial, None),
    "battery_percent":    (102, 1, _u(), "%"),
    "time_remaining_raw": (104, 1, _u(), None),  # unit unverified
    "dc_output_power":    (140, 1, _u(), "W"),
    "ac_output_power":    (142, 1, _u(), "W"),
    "dc_input_power":     (144, 1, _u(), "W"),
    "ac_input_power":     (146, 1, _u(), "W"),
    "ac_input_voltage":   (1314, 1, _u(0.1), "V"),
    "ac_output_on":       (2011, 1, _bool, None),
    "dc_output_on":       (2012, 1, _bool, None),
    "dc_eco_on":          (2014, 1, _bool, None),
    "dc_eco_time_mode":   (2015, 1, _u(), None),
    "dc_eco_min_power":   (2016, 1, _u(), "W"),
    "ac_eco_on":          (2017, 1, _bool, None),
    "ac_eco_time_mode":   (2018, 1, _u(), None),
    "ac_eco_min_power":   (2019, 1, _u(), "W"),
    "charging_mode":      (2020, 1, _u(), None),
    "power_lifting_on":   (2021, 1, _bool, None),
}


@dataclass
class DeviceState:
    """Register table built up from successive dumps."""
    registers: dict[int, int] = field(default_factory=dict)
    status: dict[str, str] = field(default_factory=dict)

    def apply(self, msg: RegisterBlock | StatusText) -> None:
        if isinstance(msg, RegisterBlock):
            for i, w in enumerate(msg.words):
                self.registers[msg.start + i] = w
        else:
            self.status.update(msg.fields)

    def values(self, fields=EL30V2_FIELDS) -> dict[str, object]:
        out = {}
        for name, (addr, size, dec, _unit) in fields.items():
            words = [self.registers.get(addr + i) for i in range(size)]
            if None in words:
                continue
            value = dec(words)
            if value is not None:
                out[name] = round(value, 2) if isinstance(value, float) else value
        return out


# ---------- MQTT 3.1.1 framing ----------

def iter_mqtt_packets(buf: bytes):
    """Yield (packet_type, flags, body) for each complete packet in buf."""
    i = 0
    while i < len(buf):
        header = buf[i]
        length, mult, j = 0, 1, i + 1
        while True:
            if j >= len(buf):
                return
            b = buf[j]
            length += (b & 0x7F) * mult
            mult *= 128
            j += 1
            if not b & 0x80:
                break
        if j + length > len(buf):
            return
        yield header >> 4, header & 0x0F, buf[j:j + length]
        i = j + length


def split_publish(flags: int, body: bytes) -> tuple[str, bytes]:
    tl = struct.unpack(">H", body[:2])[0]
    topic = body[2:2 + tl].decode("utf-8", "replace")
    rest = body[2 + tl:]
    if (flags >> 1) & 3:  # QoS > 0 carries a packet id
        rest = rest[2:]
    return topic, rest


# ---------- pcap input ----------

def tcp_streams_from_pcap(path: str, port: int = 18760) -> dict[tuple, bytes]:
    """Reassemble the client→server byte stream of each TCP connection to `port`."""
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise SystemExit(f"{path}: not a classic pcap file (pcapng is not supported)")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    l2 = {1: 14, 113: 16, 276: 20}.get(linktype)
    if l2 is None:
        raise SystemExit(f"{path}: unsupported link type {linktype}")
    segments: dict[tuple, dict[int, bytes]] = {}
    off = 24
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        pkt = data[off + 16:off + 16 + incl]
        off += 16 + incl
        ip = pkt[l2:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        tcp = ip[ihl:total]
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        payload = tcp[(tcp[12] >> 4) * 4:]
        if dport != port or not payload:
            continue
        key = (ip[12:16], sport)
        segments.setdefault(key, {})[seq] = payload
    return {k: b"".join(v[s] for s in sorted(v)) for k, v in segments.items()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("pcap", help="classic pcap file (tcpdump -w)")
    ap.add_argument("--raw", action="store_true", help="also print every register block")
    ap.add_argument("--port", type=int, default=18760)
    args = ap.parse_args(argv)

    for (_src, sport), stream in tcp_streams_from_pcap(args.pcap, args.port).items():
        print(f"== connection from port {sport}")
        state = DeviceState()
        for ptype, flags, body in iter_mqtt_packets(stream):
            if ptype != 3:
                continue
            topic, payload = split_publish(flags, body)
            try:
                msg = parse_payload(payload)
            except DecodeError as e:
                print(f"  {topic.split('/')[1] if '/' in topic else topic}: {e}")
                continue
            state.apply(msg)
            if isinstance(msg, StatusText):
                print(f"  status: {msg.fields}")
            elif args.raw:
                print(f"  block {msg.start}..{msg.start + len(msg.words) - 1}: "
                      + " ".join(f"{w:04x}" for w in msg.words))
        vals = state.values()
        vals.pop("device_sn", None)  # keep serials out of terminal logs
        for k, v in vals.items():
            unit = EL30V2_FIELDS[k][3]
            print(f"  {k:20} {v}{' ' + unit if unit else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
