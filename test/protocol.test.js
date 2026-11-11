// Simulated Bluetti device (Node crypto) talking to proto.js through fragmented notifications.
const fs = require('fs'), vm = require('vm'), nc = require('crypto'), assert = require('assert');
vm.runInThisContext(fs.readFileSync(__dirname + '/../dist/noble.min.js', 'utf8'));
globalThis.Noble = Noble;
const BT = require('../src/proto.js');
const { hex, fromHex, concat, crc16 } = BT;

const md5 = (b) => new Uint8Array(nc.createHash('md5').update(b).digest());
const aes = (dir, key, iv, data) => {
  const c = (dir ? nc.createCipheriv : nc.createDecipheriv)(`aes-${key.length * 8}-cbc`, key, iv);
  c.setAutoPadding(false);
  return new Uint8Array(Buffer.concat([c.update(data), c.final()]));
};
const sum16 = (b) => { const s = b.reduce((a, x) => a + x, 0) & 0xffff; return Uint8Array.of(s >> 8, s & 0xff); };
const kex = (body) => concat(Uint8Array.of(0x2a, 0x2a), body, sum16(body));
const encStatic = (d, k, iv) => { const p = new Uint8Array(Math.ceil(d.length / 16) * 16); p.set(d); return concat(Uint8Array.of(d.length >> 8, d.length & 255), aes(1, k, iv, p)); };
const encRand = (d, k) => { const seed = nc.randomBytes(4); const p = new Uint8Array(Math.ceil(d.length / 16) * 16); p.set(d); return concat(Uint8Array.of(d.length >> 8, d.length & 255), seed, aes(1, k, md5(seed), p)); };
const decStatic = (d, k, iv) => aes(0, k, iv, d.subarray(2)).slice(0, (d[0] << 8) | d[1]);
const decRand = (d, k) => aes(0, k, md5(d.subarray(2, 6)), d.subarray(6)).slice(0, (d[0] << 8) | d[1]);

function makeDevice({ encrypted, regs, fragment = 20 }) {
  const dev = { encrypted, regs, notify: null, writes: [] };
  const k2 = nc.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  dev.k2Spki = new Uint8Array(k2.publicKey.export({ type: 'spki', format: 'der' }));
  const l1Pub = nc.createPublicKey({ key: { ...BT.PRIVATE_KEY_L1_JWK, d: undefined }, format: 'jwk' });
  let iv, key, secure, ecdh;
  const send = (u8) => { for (let i = 0; i < u8.length; i += fragment) setTimeout(() => dev.notify(u8.slice(i, i + fragment)), 1); };
  const modbus = (cmd) => {
    assert.strictEqual(crc16(cmd.subarray(0, -2)), cmd[6] | (cmd[7] << 8), 'cmd crc');
    const addr = (cmd[2] << 8) | cmd[3], v = (cmd[4] << 8) | cmd[5];
    let resp;
    if (cmd[1] === 3) {
      const data = new Uint8Array(v * 2);
      for (let i = 0; i < v; i++) { const w = regs[addr + i] ?? 0; data[2 * i] = w >> 8; data[2 * i + 1] = w & 255; }
      resp = concat(Uint8Array.of(1, 3, v * 2), data);
    } else { regs[addr] = v; resp = cmd.slice(0, 6); }
    const c = crc16(resp); resp = concat(resp, Uint8Array.of(c & 255, c >> 8));
    return resp;
  };
  dev.subscribed = () => {
    if (!encrypted) return;
    const ch = nc.randomBytes(4);
    iv = md5(Uint8Array.from(ch).reverse());
    key = iv.map((b, i) => b ^ BT.LOCAL_AES_KEY[i]);
    send(kex(concat(Uint8Array.of(1, 4), ch)));
  };
  dev.write = async (u8) => {
    dev.writes.push(u8);
    if (!encrypted) return send(modbus(u8));
    if (u8[0] === 0x2a && u8[1] === 0x2a && !secure && u8[2] === 2) {
      assert.strictEqual(hex(u8.subarray(4, 8)), hex(iv.subarray(8, 12)), 'challenge response');
      assert.strictEqual(hex(u8.subarray(-2)), hex(sum16(u8.subarray(2, -2))));
      send(kex(Uint8Array.of(3, 1, 0)));
      ecdh = nc.createECDH('prime256v1'); ecdh.generateKeys();
      const pub = new Uint8Array(ecdh.getPublicKey()).slice(1);
      const sig = nc.sign('sha256', concat(pub, iv), { key: k2.privateKey, dsaEncoding: 'ieee-p1363' });
      setTimeout(() => send(encStatic(kex(concat(Uint8Array.of(4, 0x80), pub, sig)), key, iv)), 5);
      return;
    }
    if (!secure) {
      const m = decStatic(u8, key, iv);
      assert.strictEqual(m[2], 5);
      const body = m.subarray(2, -2), theirPub = body.subarray(2, 66), sig = body.subarray(66, 130);
      assert.ok(nc.verify('sha256', concat(theirPub, iv), { key: l1Pub, dsaEncoding: 'ieee-p1363' }, sig), 'L1 signature');
      secure = new Uint8Array(ecdh.computeSecret(concat(Uint8Array.of(4), theirPub)));
      dev.secure = secure;
      send(encStatic(kex(Uint8Array.of(6, 1, 0)), key, iv));
      return;
    }
    send(encRand(modbus(decRand(u8, secure)), secure));
  };
  return dev;
}

async function run(encrypted) {
  const regs = { 102: 87, 140: 12, 142: 345, 144: 0, 146: 210, 2011: 1, 2012: 0 };
  'AC180\0'.split('').forEach(() => {});
  // device type "AC180" at 110, byte-swapped
  const t = Buffer.from('AC180\0\0\0\0\0\0\0'); for (let i = 0; i < 6; i++) regs[110 + i] = (t[2 * i + 1] << 8) | t[2 * i];
  const dev = makeDevice({ encrypted, regs, fragment: 20 });
  const lines = [];
  const s = new BT.Session({ write: dev.write, k2Spki: dev.k2Spki, log: (d, l, u8) => lines.push(d + ' ' + l + (u8 ? ' ' + hex(u8) : '')) });
  dev.notify = (u8) => s.onNotify(u8);
  setTimeout(dev.subscribed, 10);
  await s.start(300, 3000);
  assert.strictEqual(s.mode, encrypted ? 'encrypted' : 'plain');
  if (encrypted) assert.strictEqual(hex(s.secureKey), hex(dev.secure), 'shared secret');
  const type = BT.decodeType(await s.readRegs(110, 6), true);
  assert.strictEqual(type, 'AC180');
  const model = BT.MODELS[type];
  const words = new Map();
  for (const r of BT.pollRanges(model)) {
    const d = await s.readRegs(r.start, r.qty);
    for (let i = 0; i < r.qty; i++) words.set(r.start + i, (d[2 * i] << 8) | d[2 * i + 1]);
  }
  const st = BT.parseStatus(model, words);
  assert.deepStrictEqual(st, { soc: 87, dcIn: 0, acIn: 210, acOut: 345, dcOut: 12, acOn: true, dcOn: false });
  await s.writeReg(model.ctrlDc, 1);
  assert.strictEqual(regs[2012], 1);
  // concurrent requests must serialise
  const [a, b] = await Promise.all([s.readRegs(102, 1), s.readRegs(2011, 2)]);
  assert.strictEqual(a[1], 87); assert.strictEqual(b[3], 1);
  console.log(`${encrypted ? 'encrypted' : 'plain'}: OK  ranges=${JSON.stringify(BT.pollRanges(model))} status=${JSON.stringify(st)}`);
  if (encrypted) console.log(lines.filter((l) => l.startsWith('st')).slice(0, 9).join('\n'));
}
(async () => { await run(false); await run(true); })().catch((e) => { console.error('FAIL', e); process.exit(1); });
