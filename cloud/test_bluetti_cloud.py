"""Unit tests for bluetti_cloud.py, using synthetic payloads (no real serials)."""
import struct
import unittest

import bluetti_cloud as bc


def with_crc(frame: bytes) -> bytes:
    c = bc.crc16(frame)
    return frame + bytes([c & 0xFF, c >> 8])


def dump(start: int, words: list[int], seq: int = 2) -> bytes:
    data = b"".join(struct.pack(">H", w) for w in words)
    frame = with_crc(bytes([1, 0x10]) + struct.pack(">HHB", start, len(words), len(data)) + data)
    return b"\x01\xf8\x01\x10" + struct.pack(">H", seq) + b"\x14\xed\x00\x00" + frame


def read_response(start: int, words: list[int]) -> bytes:
    data = b"".join(struct.pack(">H", w) for w in words)
    frame = with_crc(bytes([1, 3, len(data)]) + data)
    return b"\x01\xf8\x0f" + struct.pack(">H", start) + b"\x00\x00\xed\x00\x00" + frame


def publish(topic: str, payload: bytes) -> bytes:
    body = struct.pack(">H", len(topic)) + topic.encode() + payload
    n, rem = len(body), b""
    while True:
        b, n = n & 0x7F, n >> 7
        rem += bytes([b | (0x80 if n else 0)])
        if not n:
            return b"\x30" + rem + body


class DecoderTest(unittest.TestCase):
    def test_crc_matches_known_frame(self):
        # read 6 registers from 110: a frame bluetti-bt-lib sends over BLE
        self.assertEqual(with_crc(bytes.fromhex("0103006e0006")).hex(), "0103006e0006a415")

    def test_dump_and_values(self):
        regs_100 = [0] * 100
        regs_100[2] = 87                                   # 102 battery %
        regs_100[10:13] = [0x4C45, 0x3033, 0x3256]         # 110 "EL30V2" byte-swapped
        regs_100[40:47] = [12, 0, 345, 0, 0, 0, 210]       # 140..146 power
        state = bc.DeviceState()
        state.apply(bc.parse_payload(dump(100, regs_100)))
        state.apply(bc.parse_payload(dump(1300, [0] * 14 + [2311])))
        state.apply(bc.parse_payload(read_response(2011, [1, 0])))
        v = state.values()
        self.assertEqual(v["device_type"], "EL30V2")
        self.assertEqual(v["battery_percent"], 87)
        self.assertEqual((v["dc_output_power"], v["ac_output_power"], v["ac_input_power"]), (12, 345, 210))
        self.assertEqual(v["ac_input_voltage"], 231.1)
        self.assertIs(v["ac_output_on"], True)
        self.assertIs(v["dc_output_on"], False)

    def test_status_text(self):
        p = b"\x01\xf8\x02\x00\x00\x00\x00\xed\x00\x00\x01\x49" + b'"ac_sw=1,soc=94"' + b"1d"
        self.assertEqual(bc.parse_payload(p).fields, {"ac_sw": "1", "soc": "94"})

    def test_bad_crc_rejected(self):
        p = bytearray(dump(100, [1, 2, 3]))
        p[-1] ^= 0xFF
        with self.assertRaises(bc.DecodeError):
            bc.parse_payload(bytes(p))

    def test_mqtt_framing_split_and_multi_byte_length(self):
        big = publish("PUB/EL30V2/0", dump(100, list(range(100))))   # >127 bytes
        small = publish("PUB/EL30V2/0", read_response(2011, [1]))
        packets = list(bc.iter_mqtt_packets(big + small + b"\xc0\x00" + small[:5]))
        self.assertEqual([p[0] for p in packets], [3, 3, 12])         # partial tail dropped
        topic, payload = bc.split_publish(packets[0][1], packets[0][2])
        self.assertEqual(topic, "PUB/EL30V2/0")
        self.assertEqual(bc.parse_payload(payload).words[5], 5)


if __name__ == "__main__":
    unittest.main()
