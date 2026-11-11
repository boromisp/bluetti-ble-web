/* Bluetti BLE protocol core: Modbus framing, encryption handshake, register maps.
 * Ported from nhurman/bluetti_mqtt (encryption.py) and Patrick762/bluetti-bt-lib.
 * Needs globalThis.crypto.subtle and a global `Noble` with { cbc, md5 }. */
const BT = (() => {
  'use strict';
  const subtle = globalThis.crypto.subtle;

  // ---------- byte helpers ----------
  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
  const fromHex = (s) => Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)));
  const concat = (...arrs) => {
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  const u16 = (n) => Uint8Array.of((n >> 8) & 0xff, n & 0xff);
  const startsKex = (u8) => u8.length >= 2 && u8[0] === 0x2a && u8[1] === 0x2a;

  // ---------- Modbus ----------
  function crc16(buf) {
    let crc = 0xffff;
    for (const b of buf) {
      crc ^= b;
      for (let i = 0; i < 8; i++) crc = crc & 1 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
    }
    return crc;
  }
  function withCrc(body) {
    const c = crc16(body);
    return concat(body, Uint8Array.of(c & 0xff, c >> 8)); // CRC little-endian
  }
  const readCmd = (addr, qty) => withCrc(concat(Uint8Array.of(1, 3), u16(addr), u16(qty)));
  const writeCmd = (addr, val) => withCrc(concat(Uint8Array.of(1, 6), u16(addr), u16(val)));
  const crcOk = (f) => f.length >= 4 && crc16(f.subarray(0, -2)) === (f[f.length - 2] | (f[f.length - 1] << 8));

  // Joins Modbus RTU frames that arrive split across notifications.
  class ModbusAssembler {
    constructor() { this.buf = new Uint8Array(0); }
    reset() { this.buf = new Uint8Array(0); }
    expected() {
      const b = this.buf;
      if (b.length < 3) return null;
      if (b[1] & 0x80) return 5;               // exception: addr fn code crc crc
      if (b[1] === 3 || b[1] === 4) return 5 + b[2]; // addr fn count data.. crc crc
      if (b[1] === 6 || b[1] === 16) return 8;
      return b.length;                         // unknown function: take what we have
    }
    push(chunk) {
      this.buf = concat(this.buf, chunk);
      const frames = [];
      for (;;) {
        const n = this.expected();
        if (n == null || this.buf.length < n) break;
        frames.push(this.buf.slice(0, n));
        this.buf = this.buf.slice(n);
      }
      return frames;
    }
  }

  // ---------- encryption constants (from encryption.py) ----------
  const LOCAL_AES_KEY = fromHex('459FC535808941F17091E0993EE3E93D');
  const PUBLIC_KEY_K2_SPKI = fromHex('3059301306072a8648ce3d020106082a8648ce3d03010703420004A73ABF5D2232C8C1C72E68304343C272495E3A8FD6F30EA96DE2F4B3CE60B251EE21AC667CF8A71E18B46B664EAEFFE3C489F24F695B6411DB7E22CCC85A8594');
  // PRIVATE_KEY_L1 (4F19A16E…F337) as a JWK; x/y derived offline from d.
  const PRIVATE_KEY_L1_JWK = { kty: 'EC', crv: 'P-256', d: 'Txmhbj6Hvdm9JNPlSVuIBBURlDy8i5aa3pZB0PVq8zc', x: 'PynhuLKdhCK7sODwkADPLuKTHaE82sgSn4wJ3qwH9Rk', y: 'taxVCco_P1myNLd3eiMa5ZXKWqF0X9emK8TQIDcRfdE', ext: true };

  const sum16 = (body) => u16(body.reduce((s, b) => s + b, 0) & 0xffff);
  const kexFrame = (body) => concat(Uint8Array.of(0x2a, 0x2a), body, sum16(body));
  // "2a2a <type> <x> <data…> <cksum16>"
  function parseKex(u8) {
    const body = u8.subarray(2, -2);
    return { type: body[0], data: body.subarray(2), checksumOk: eq(sum16(body), u8.subarray(-2)) };
  }

  function aesEncrypt(data, key, iv) {
    let header = u16(data.length);
    if (iv == null) {
      const seed = globalThis.crypto.getRandomValues(new Uint8Array(4));
      iv = Noble.md5(seed);
      header = concat(header, seed);
    }
    const padded = new Uint8Array(Math.ceil(data.length / 16) * 16);
    padded.set(data);
    return concat(header, Noble.cbc(key, iv, { disablePadding: true }).encrypt(padded));
  }
  function aesDecrypt(data, key, iv) {
    const len = (data[0] << 8) | data[1];
    let enc;
    if (iv == null) { iv = Noble.md5(data.subarray(2, 6)); enc = data.subarray(6); }
    else enc = data.subarray(2);
    if (enc.length % 16 !== 0) throw new Error('Data not aligned on AES block size');
    return Noble.cbc(key, iv, { disablePadding: true }).decrypt(enc).slice(0, len);
  }

  // ---------- register maps (from bluetti-bt-lib devices/*.py) ----------
  const DEVICE_NAME_RE = /^(AC2A|AC2P|AC50B|AC60|AC60P|AC70|AC70P|AC180|AC180T|AC180P|AC200L|AC200M|AC200PL|AC300|AC500|AP300|EB3A|EL10|EL100V2|EL30V2|EP500|EP500P|EP600|EP760|EP800|EP2000|Handsfree\s[12]|PR30V2|PR100V2)(\d+)$/;
  // Minimal set of prefixes covering every name above, plus PBOX (scan script accepts it).
  const NAME_PREFIXES = ['AC2A', 'AC2P', 'AC50B', 'AC60', 'AC70', 'AC180', 'AC200', 'AC300', 'AC500', 'AP300', 'EB3A', 'EL10', 'EL30', 'EP500', 'EP600', 'EP760', 'EP800', 'EP2000', 'Handsfree', 'PR30', 'PR100', 'PBOX'];

  // Field kinds: 'u' UInt, 'b' BoolField (0/1 else null), 'nz' BoolFieldNonZero (==1)
  const V1 = { v: 1, soc: 43, dcIn: 36, acIn: 37, acOut: 38, dcOut: 39 };
  const V2 = { v: 2, soc: 102 };
  const V2P = { ...V2, dcOut: 140, acOut: 142, dcIn: 144, acIn: 146 };
  const V1C = { ...V1, acOn: [3007, 'b'], dcOn: [3008, 'b'], ctrlAc: 3007, ctrlDc: 3008 };
  const V2C = { ...V2P, acOn: [2011, 'b'], dcOn: [2012, 'b'], ctrlAc: 2011, ctrlDc: 2012 };
  const MODELS = {
    AC200L: V1C, AC200M: V1C, AC200PL: V1C, AC300: V1C, AC500: V1C, EB3A: V1C, EP500: V1C, EP500P: V1C,
    AC180: V2C, AC180P: V2C, AC60: V2C, AC60P: V2C, AC70: V2C, EL10: V2C, EL100V2: V2C, EL30V2: V2C, 'Handsfree 2': V2C,
    AC180T: V2P, AC70P: V2P, AP300: V2P, 'Handsfree 1': V2P, PR100V2: V2P, PR30V2: V2P,
    AC50B: { v: 2, soc: 102, dcOut: 140, acOut: 142, acIn: 146 },
    AC2A: { ...V2P, acOn: [1509, 'b'], dcOn: [2012, 'b'] },
    AC2P: { ...V2P, acOn: [2011, 'nz'], dcOn: [2012, 'nz'], ctrlAc: 2011, ctrlDc: 2012 },
    EP600: { ...V2, acOn: [2011, 'b'], ctrlAc: 2011 },
    EP760: { ...V2, acOn: [2208, 'b'], ctrlAc: 2208 },
    EP2000: { ...V2, acOn: [2011, 'b'] },
    EP800: { ...V2 },
  };
  const modelFromName = (name) => {
    const m = name && DEVICE_NAME_RE.exec(name.trim());
    return m ? m[1].replace(/\s+/, ' ') : null;
  };

  // Group the addresses we need into a few contiguous reads.
  function pollRanges(model) {
    const addrs = new Set();
    for (const k of ['soc', 'dcIn', 'acIn', 'acOut', 'dcOut']) if (model[k] != null) addrs.add(model[k]);
    for (const k of ['acOn', 'dcOn']) if (model[k]) addrs.add(model[k][0]);
    const sorted = [...addrs].sort((a, b) => a - b);
    const ranges = [];
    for (const a of sorted) {
      const r = ranges[ranges.length - 1];
      if (r && a - (r.start + r.qty - 1) <= 8 && a - r.start < 32) r.qty = a - r.start + 1;
      else ranges.push({ start: a, qty: 1 });
    }
    return ranges;
  }

  function parseStatus(model, words) { // words: Map addr -> uint16
    const u = (a) => (a == null || !words.has(a) ? null : words.get(a));
    const bool = (spec) => {
      if (!spec) return null;
      const v = u(spec[0]);
      if (v == null) return null;
      if (spec[1] === 'nz') return v === 1;
      return v === 0 ? false : v === 1 ? true : null;
    };
    const soc = u(model.soc);
    return {
      soc: soc != null && soc <= 100 ? soc : null,
      dcIn: u(model.dcIn), acIn: u(model.acIn), acOut: u(model.acOut), dcOut: u(model.dcOut),
      acOn: bool(model.acOn), dcOn: bool(model.dcOn),
    };
  }

  // ---------- connection session ----------
  class Session {
    /** opts: { write(u8): Promise, log(dir, label, u8|null, text?), onState(s), k2Spki?, timeoutMs? } */
    constructor(opts) {
      this.o = opts;
      this.k2Spki = opts.k2Spki || PUBLIC_KEY_K2_SPKI;
      this.timeoutMs = opts.timeoutMs || 5000;
      this.mode = 'detect';           // detect | plain | encrypted
      this.hs = 'waiting';            // handshake state for display
      this.modbus = new ModbusAssembler();
      this.encBuf = new Uint8Array(0);
      this.unsecureKey = this.unsecureIv = this.secureKey = null;
      this.pending = null;
      this.chain = Promise.resolve();
      this.queue = Promise.resolve(); // serialises notification handling (crypto is async)
      this._firstNotify = null;
      this._ready = null;
    }
    log(...a) { this.o.log(...a); }
    setHs(s, extra) { this.hs = s; this.log('st', 'handshake: ' + s + (extra ? ' – ' + extra : '')); this.o.onState && this.o.onState(this); }

    async raw(u8, label) { this.log('tx', label || 'TX', u8); await this.o.write(u8); }

    onNotify(u8) {
      u8 = new Uint8Array(u8);
      this.log('rx', 'RX', u8);
      this.queue = this.queue.then(() => this._handle(u8)).catch((e) => this.log('err', 'notify handler: ' + e.message));
    }

    async _handle(u8) {
      if (this._firstNotify) { const r = this._firstNotify; this._firstNotify = null; r(u8); }
      if (this.mode === 'detect') {
        this.mode = startsKex(u8) ? 'encrypted' : 'plain';
        this.log('st', 'mode: ' + this.mode + ' (first notification ' + (startsKex(u8) ? 'starts with 2a2a' : 'is not 2a2a') + ')');
      } else if (this.mode === 'plain' && startsKex(u8) && this.modbus.buf.length === 0 && u8[2] === 1) {
        this.mode = 'encrypted';
        this.log('st', 'mode: switched to encrypted (late challenge)');
      }
      if (this.mode === 'plain') return this._modbusIn(u8);
      return this._encryptedIn(u8);
    }

    async _encryptedIn(u8) {
      if (this.encBuf.length === 0 && startsKex(u8)) return this._kex(parseKex(u8));
      if (!this.unsecureKey) { this.log('err', 'encrypted data before key initialisation'); return; }
      this.encBuf = concat(this.encBuf, u8);
      for (;;) {
        if (this.encBuf.length < 2) return;
        const len = (this.encBuf[0] << 8) | this.encBuf[1];
        const header = this.secureKey ? 6 : 2;
        const need = header + Math.ceil(len / 16) * 16;
        if (this.encBuf.length < need) { this.log('st', `buffering encrypted fragment ${this.encBuf.length}/${need}`); return; }
        const msg = this.encBuf.slice(0, need);
        this.encBuf = this.encBuf.slice(need);
        let plain;
        try {
          plain = this.secureKey ? aesDecrypt(msg, this.secureKey, null) : aesDecrypt(msg, this.unsecureKey, this.unsecureIv);
        } catch (e) { this.log('err', 'decrypt failed: ' + e.message); this.encBuf = new Uint8Array(0); return; }
        this.log('rx', 'RX plain', plain);
        if (startsKex(plain)) await this._kex(parseKex(plain));
        else this._modbusIn(plain);
      }
    }

    async _kex(m) {
      if (!m.checksumOk) this.log('err', 'kex checksum mismatch (continuing, as bluetti-bt-lib does)');
      try {
        if (m.type === 1) {                      // CHALLENGE
          if (m.data.length !== 4) throw new Error('challenge length ' + m.data.length);
          this.unsecureIv = Noble.md5(m.data.slice().reverse());
          this.unsecureKey = this.unsecureIv.map((b, i) => b ^ LOCAL_AES_KEY[i]);
          this.setHs('challenge received', 'iv ' + hex(this.unsecureIv) + ' key ' + hex(this.unsecureKey));
          await this.raw(kexFrame(concat(Uint8Array.of(2, 4), this.unsecureIv.subarray(8, 12))), 'TX challenge resp');
          this.setHs('challenge answered');
        } else if (m.type === 3) {               // CHALLENGE_ACCEPTED
          if (m.data.length !== 1 || m.data[0] !== 0) throw new Error('challenge rejected: ' + hex(m.data));
          this.setHs('challenge accepted');
        } else if (m.type === 4) {               // PEER_PUBKEY (signed)
          if (m.data.length !== 128) throw new Error('peer pubkey length ' + m.data.length);
          const peerPub = m.data.slice(0, 64), sig = m.data.slice(64);
          const k2 = await subtle.importKey('spki', this.k2Spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
          const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k2, sig, concat(peerPub, this.unsecureIv));
          if (!ok) throw new Error('peer pubkey signature invalid');
          this.peerKey = await subtle.importKey('raw', concat(Uint8Array.of(4), peerPub), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
          this.setHs('peer pubkey verified');
          const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
          this.myPriv = kp.privateKey;
          const myPub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey)).slice(1);
          const l1 = await subtle.importKey('jwk', PRIVATE_KEY_L1_JWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
          const mySig = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, l1, concat(myPub, this.unsecureIv)));
          const msg = kexFrame(concat(Uint8Array.of(5, 0x80), myPub, mySig));
          this.log('tx', 'TX plain', msg);
          await this.raw(aesEncrypt(msg, this.unsecureKey, this.unsecureIv), 'TX our pubkey');
          this.setHs('our pubkey sent');
        } else if (m.type === 6) {               // PUBKEY_ACCEPTED
          if (m.data.length !== 1 || m.data[0] !== 0) throw new Error('key rejected: ' + hex(m.data));
          this.secureKey = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: this.peerKey }, this.myPriv, 256));
          this.setHs('ready', 'secure key ' + hex(this.secureKey));
          if (this._ready) this._ready.resolve();
        } else {
          this.log('err', 'unknown kex message type ' + m.type);
        }
      } catch (e) {
        this.hsError = e;
        this.setHs('failed', e.message);
        if (this._ready) this._ready.reject(e);
      }
    }

    _modbusIn(u8) {
      for (const f of this.modbus.push(u8)) {
        if (f.length !== u8.length) this.log('rx', 'RX joined frame', f);
        if (!this.pending) { this.log('st', 'unsolicited frame ' + hex(f)); continue; }
        const p = this.pending; this.pending = null; clearTimeout(p.timer);
        if (!crcOk(f)) p.reject(new Error('CRC error in ' + hex(f)));
        else if (f[1] & 0x80) p.reject(new Error('Modbus exception code ' + f[2]));
        else p.resolve(f);
      }
    }

    /** After notifications are started: decide plain vs encrypted and finish the handshake. */
    async start(detectMs = 3000, handshakeMs = 20000) {
      const first = new Promise((r) => { this._firstNotify = r; });
      const got = await Promise.race([first, new Promise((r) => setTimeout(() => r(null), detectMs))]);
      if (!got) {
        this._firstNotify = null;
        if (this.mode === 'detect') { this.mode = 'plain'; this.log('st', `mode: plain (no notification within ${detectMs} ms)`); }
      }
      await this.queue;
      if (this.mode === 'plain') { this.hs = 'n/a (plain)'; this.o.onState && this.o.onState(this); return; }
      if (this.secureKey) return;
      if (this.hsError) throw this.hsError;
      await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('handshake timeout (state: ' + this.hs + ')')), handshakeMs);
        this._ready = { resolve: () => { clearTimeout(t); resolve(); }, reject: (e) => { clearTimeout(t); reject(e); } };
      });
    }

    /** Send one Modbus command, wait for the joined response frame. Serialised. */
    request(cmd) {
      const run = async () => {
        if (this.mode === 'encrypted' && !this.secureKey) throw new Error('encryption handshake not finished');
        this.modbus.reset();
        this.encBuf = new Uint8Array(0);
        const resp = new Promise((resolve, reject) => {
          this.pending = { resolve, reject, timer: setTimeout(() => { this.pending = null; reject(new Error('response timeout')); }, this.timeoutMs) };
        });
        resp.catch(() => {});
        if (this.mode === 'encrypted') {
          this.log('tx', 'TX plain', cmd);
          await this.raw(aesEncrypt(cmd, this.secureKey, null));
        } else await this.raw(cmd);
        return resp;
      };
      const p = this.chain.then(run, run);
      this.chain = p.catch(() => {});
      return p;
    }

    async readRegs(start, qty) {
      const f = await this.request(readCmd(start, qty));
      const data = f.subarray(3, -2);
      if (data.length !== qty * 2) throw new Error(`expected ${qty * 2} data bytes, got ${data.length}`);
      return data;
    }
    async writeReg(addr, val) {
      const cmd = writeCmd(addr, val);
      const f = await this.request(cmd);
      if (!eq(f, cmd)) this.log('st', 'write echo differs: ' + hex(f));
      return f;
    }
  }

  // Device type strings: V2 at 110 (byte-swapped), V1 at 10 (plain), 6 registers each.
  function decodeType(data, swap) {
    const b = data.slice();
    if (swap) for (let i = 0; i + 1 < b.length; i += 2) [b[i], b[i + 1]] = [b[i + 1], b[i]];
    let end = b.length; while (end > 0 && b[end - 1] === 0) end--;
    return Array.from(b.subarray(0, end), (c) => (c < 128 ? String.fromCharCode(c) : '')).join('');
  }

  return { hex, fromHex, concat, crc16, readCmd, writeCmd, ModbusAssembler, aesEncrypt, aesDecrypt, kexFrame, parseKex,
    LOCAL_AES_KEY, PRIVATE_KEY_L1_JWK, DEVICE_NAME_RE, NAME_PREFIXES, MODELS, modelFromName, pollRanges, parseStatus,
    decodeType, Session };
})();
if (typeof module !== 'undefined') module.exports = BT;
