/* 运行时：解密点阵 -> 画到 canvas。链接字符串从不出现在 DOM / 网络 / 内存中 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  // ---- 与 tools/build.mjs 对齐的常量 ----
  const IT = 210000;
  const MAGIC = 0x51;
  const MASK = [
    [0x5a, 0x11, 0x9c, 0x42, 0xe7, 0x08, 0x6d, 0xb3],
    [0x2f, 0x84, 0x3d, 0xc6, 0x51, 0x9a, 0x07, 0xe2],
    [0x71, 0xca, 0x05, 0x38, 0x9f, 0x24, 0xdc, 0x6a],
    [0xbe, 0x37, 0x60, 0xd5, 0x0a, 0x7c, 0x93, 0x1e]
  ];

  // 调试环境检测开关：false 则只保留静默防护（禁右键/禁快捷键/禁导出）
  const STRICT = true;

  const MARGIN = 4;   // 二维码静区模块数

  let SEC = null;
  let locked = false;
  let busy = false;

  // ---------- 基础 ----------
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  function assembleSecret(P) {
    const out = new Uint8Array(32);
    for (let j = 0; j < 4; j++) {
      const idx = P.o[j];
      const b = b64(P.s[j]);
      for (let k = 0; k < 8; k++) out[idx * 8 + k] = b[k] ^ MASK[idx][k];
    }
    return out;
  }

  const wipe = (u8) => { if (u8) u8.fill(0); };

  // ---------- UI ----------
  function hint(msg, err) {
    const el = $('hint');
    if (!el) return;
    el.textContent = msg;
    el.classList.toggle('err', !!err);
  }

  function clearQR() {
    const cv = $('qr');
    if (cv && cv.width) {
      const ctx = cv.getContext('2d');
      ctx.clearRect(0, 0, cv.width, cv.height);
      cv.width = cv.height = 0;
    }
    if (cv) cv.classList.remove('on');
    const f = document.querySelector('.frame');
    if (f) f.classList.remove('on');
  }

  function lock(msg) {
    if (locked) return;
    locked = true;
    wipe(SEC);
    SEC = null;
    clearQR();
    hint('', false);
    const v = $('lock');
    if (v) {
      const m = $('lock-msg');
      if (m && msg) m.textContent = msg;
      v.hidden = false;
    }
    const go = $('go');
    if (go) go.disabled = true;
    const sel = $('ch');
    if (sel) sel.disabled = true;
  }

  // ---------- 绘制 ----------
  function draw(size, bytes) {
    const cv = $('qr');
    const dim = size + MARGIN * 2;
    // 按可用宽度取整数倍，画布按 1:1 像素输出，不做缩放重采样
    const stage = document.querySelector('.stage');
    const avail = Math.max(160, (stage ? stage.clientWidth : 280) - 2);
    const scale = Math.max(2, Math.floor(avail / dim));
    const px = dim * scale;

    cv.width = px;
    cv.height = px;
    cv.classList.remove('on');

    const ctx = cv.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, px, px);
    ctx.fillStyle = '#000000';

    const bits = size * size;
    const o = MARGIN * scale;
    for (let i = 0; i < bits; i++) {
      if (bytes[i >> 3] & (0x80 >> (i & 7))) {
        const x = i % size;
        const y = (i / size) | 0;
        ctx.fillRect(o + x * scale, o + y * scale, scale, scale);
      }
    }

    const f = document.querySelector('.frame');
    if (f) f.classList.add('on');
    cv.classList.add('on');
  }

  // ---------- 解密 ----------
  async function open(item) {
    const raw = b64(item.d);
    const salt = raw.subarray(0, 16);
    const iv = raw.subarray(16, 28);
    const tag = raw.subarray(raw.length - 16);
    const ct = raw.subarray(28, raw.length - 16);

    const body = new Uint8Array(ct.length + tag.length);
    body.set(ct, 0);
    body.set(tag, ct.length);

    const base = await crypto.subtle.importKey('raw', SEC, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: IT, hash: 'SHA-256' }, base, 256
    );
    const key = await crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['decrypt']);

    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(item.i), tagLength: 128 },
      key, body
    ));

    wipe(new Uint8Array(bits));
    return plain;
  }

  // ---------- 防护 ----------
  function shield() {
    // 右键 / 长按菜单 / 选中 / 拖拽
    document.addEventListener('contextmenu', (e) => e.preventDefault(), true);
    document.addEventListener('selectstart', (e) => e.preventDefault(), true);
    document.addEventListener('dragstart', (e) => e.preventDefault(), true);

    // 快捷键：F12 / Ctrl+Shift+I,J,C / Ctrl+U / Ctrl+S / Ctrl+P
    document.addEventListener('keydown', (e) => {
      const k = (e.key || '').toLowerCase();
      if (e.key === 'F12') { e.preventDefault(); return; }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && 'ijc'.includes(k)) { e.preventDefault(); return; }
      if ((e.ctrlKey || e.metaKey) && 'usp'.includes(k)) { e.preventDefault(); return; }
    }, true);

    // 画布导出通道：截图脚本最常走的那几条
    const boom = () => { throw new DOMException('blocked', 'SecurityError'); };
    const C = HTMLCanvasElement.prototype;
    C.toDataURL = boom;
    C.toBlob = boom;
    if (window.CanvasRenderingContext2D) CanvasRenderingContext2D.prototype.getImageData = boom;
    if (window.OffscreenCanvas) OffscreenCanvas.prototype.convertToBlob = boom;
  }

  // 断点法：调试器开着时 debugger 语句会真的暂停，耗时立刻暴露
  function trapped() {
    if (!STRICT) return false;
    const t = performance.now();
    // eslint-disable-next-line no-debugger
    debugger;
    return performance.now() - t > 250;
  }

  // 流量噪声：留在网络面板里的是一条 404，不携带任何信息
  function noise() {
    try {
      const h = Array.from(crypto.getRandomValues(new Uint8Array(6)))
        .map((b) => b.toString(16).padStart(2, '0')).join('');
      fetch('assets/' + h + '.woff2', { cache: 'no-store', mode: 'no-cors' }).catch(() => {});
    } catch (_) { /* ignore */ }
  }

  // ---------- 主流程 ----------
  async function onGet(e) {
    if (!e.isTrusted || locked || busy) return;

    const sel = $('ch');
    const item = (window.__Q.c || []).find((x) => x.i === sel.value);
    if (!item) return;

    if (trapped()) return lock('检测到调试器，已停止服务。');

    busy = true;
    const btn = $('go');
    btn.disabled = true;
    clearQR();
    hint('正在生成', false);

    try {
      const plain = await open(item);
      if (plain[0] !== MAGIC) throw new Error('bad payload');

      const size = plain[1];
      const bytes = plain.subarray(2, 2 + Math.ceil((size * size) / 8));
      draw(size, bytes);
      wipe(plain);

      hint('60 秒内有效，切走即清除', false);
      setTimeout(() => { if (!locked) { clearQR(); hint('已清除，可重新生成', false); } }, 60000);
    } catch (err) {
      clearQR();
      hint('生成失败，刷新重试', true);
      if (err && err.name === 'OperationError') lock('解密失败，环境不可信。');
    } finally {
      busy = false;
      if (!locked) btn.disabled = false;
    }
  }

  function init() {
    const P = window.__Q;

    if (!window.crypto || !crypto.subtle) {
      return hint('需通过 https 或 localhost 访问', true);
    }
    if (window.top !== window.self) {
      return lock('禁止在框架内打开');
    }
    if (!P || !P.c || !P.c.length) {
      return lock('配置加载失败');
    }

    shield();
    noise();

    SEC = assembleSecret(P);

    const sel = $('ch');
    for (const item of P.c) {
      const o = document.createElement('option');
      o.value = item.i;
      o.textContent = item.n;
      sel.appendChild(o);
    }

    sel.addEventListener('change', () => { clearQR(); hint('未生成', false); });
    $('go').addEventListener('click', onGet);

    const rl = $('reload');
    if (rl) rl.addEventListener('click', () => location.reload());

    document.addEventListener('visibilitychange', () => {
      if (document.hidden && !locked) { clearQR(); hint('切走了，二维码已清除', false); }
    });

    hint('未生成', false);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
