// tool: node | 端到端校验：payload.js 密文 -> 组装密钥 -> AES-GCM 解密 -> 点阵 -> jsQR 解码 -> 比对原链接
// 组装逻辑与 assets/app.js 保持一致；任何一方偏差都会解出乱码点阵，jsQR 直接失败
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import jsQR from 'jsqr';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

const IT = 210000;
const MAGIC = 0x51;
const MASK = [
  [0x5a, 0x11, 0x9c, 0x42, 0xe7, 0x08, 0x6d, 0xb3],
  [0x2f, 0x84, 0x3d, 0xc6, 0x51, 0x9a, 0x07, 0xe2],
  [0x71, 0xca, 0x05, 0x38, 0x9f, 0x24, 0xdc, 0x6a],
  [0xbe, 0x37, 0x60, 0xd5, 0x0a, 0x7c, 0x93, 0x1e],
];

const ctx = { self: {}, crypto: globalThis.crypto, console };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(ROOT, 'assets', 'payload.js'), 'utf8'), ctx);
const P = ctx.self.__Q;

const b64 = (s) => Buffer.from(s, 'base64');

const sec = Buffer.alloc(32);
for (let j = 0; j < 4; j++) {
  const idx = P.o[j];
  const b = b64(P.s[j]);
  for (let k = 0; k < 8; k++) sec[idx * 8 + k] = b[k] ^ MASK[idx][k];
}

const src = JSON.parse(fs.readFileSync(
  fs.existsSync(path.join(HERE, 'channels.local.json'))
    ? path.join(HERE, 'channels.local.json')
    : path.join(HERE, 'channels.example.json'), 'utf8'));

let pass = 0, fail = 0;

for (const item of P.c) {
  const expect = src.find((s) => (s.id || '') === item.i);
  if (!expect) { console.log(`✗ ${item.i}: 源配置里找不到`); fail++; continue; }

  const raw = b64(item.d);
  const salt = raw.subarray(0, 16);
  const iv = raw.subarray(16, 28);
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(28, raw.length - 16);
  const body = Buffer.concat([ct, tag]);

  const key = crypto.pbkdf2Sync(sec, salt, IT, 32, 'sha256');
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(Buffer.from(item.i, 'utf8'));
  d.setAuthTag(tag);
  const plain = Buffer.concat([d.update(ct), d.final()]);

  if (plain[0] !== MAGIC) { console.log(`✗ ${item.n}: 魔数错`); fail++; continue; }

  // 还原成浏览器里实际绘制的像素（含 4 模块静区），再交给扫码器
  const size = plain[1];
  const bits = size * size;
  const MARGIN = 4;
  const scale = 8;
  const dim = (size + MARGIN * 2) * scale;

  const rgba = Buffer.alloc(dim * dim * 4, 255);
  for (let i = 0; i < bits; i++) {
    if (!(plain[2 + (i >> 3)] & (0x80 >> (i & 7)))) continue;
    const mx = i % size, my = (i / size) | 0;
    const x0 = (mx + MARGIN) * scale, y0 = (my + MARGIN) * scale;
    for (let y = y0; y < y0 + scale; y++) {
      for (let x = x0; x < x0 + scale; x++) {
        const o = (y * dim + x) * 4;
        rgba[o] = rgba[o + 1] = rgba[o + 2] = 0;
      }
    }
  }

  const res = jsQR(new Uint8ClampedArray(rgba), dim, dim);
  const ok = res && res.data === expect.url;
  console.log(`${ok ? '✓' : '✗'} ${item.n.padEnd(10)} ${size}x${size}  ${res ? res.data : '(扫码失败)'}`);
  if (!ok) { console.log(`   期望: ${expect.url}`); fail++; } else pass++;
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
