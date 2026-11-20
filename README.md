# 网盘二维码发放页

静态页（GitHub Pages 可直接托管）：下拉选网盘 → 点按钮 → 本地解密并绘制二维码，背景是 `assets/bg.svg`。

二维码不来自图片，也不来自接口；页面唯一请求的图片是背景 `bg.svg`，它不承载任何信息。

---

## 目录

```
index.html              页面
assets/style.css        样式（纸面 + 发丝线，背景图铺满）
assets/bg.svg           背景图
assets/app.js           运行时：解密点阵 + 防护
assets/payload.js       构建产物（只有密文，明文永不入仓）
tools/build.mjs         构建器：链接 → 点阵 → 加密 → payload.js
tools/verify.mjs        校验器：密文 → 解密 → 点阵 → 真实扫码回读
tools/channels.example.json   网盘配置样例（占位）
tools/channels.local.json     真实配置（已 gitignore）
tools/secret.local.json       主密钥（已 gitignore）
```

## 一、配置网盘

把 `tools/channels.example.json` 复制成 `tools/channels.local.json`，填真实链接：

```json
[
  { "id": "baidu", "name": "百度网盘", "url": "https://pan.baidu.com/s/1XXXXXXXXXXX" },
  { "id": "quark", "name": "夸克网盘", "url": "https://pan.quark.cn/s/xxxxxxxxxxxx" }
]
```

- `id` 唯一，参与加密认证（换 id 会解密失败）
- `name` 是下拉框里显示的文字
- `url` 是二维码内容，只存在于本地配置里

改完执行构建：

```bash
cd tools && npm install   # 首次
cd .. && node tools/build.mjs
```

首次构建会自动生成 `tools/secret.local.json`（32 字节主密钥）。**这个文件丢了，已发布的 payload.js 就只能重新构建；它本身绝不要提交。**

## 二、本地预览

```bash
python -m http.server 8123
```

打开 <http://127.0.0.1:8123/>。

必须走 `localhost` 或 `https`——WebCrypto 只在安全上下文可用，直接双击 `file://` 打开会提示。

## 三、校验

```bash
node tools/verify.mjs
```

它会读 `payload.js`、组装密钥、解密、还原成像素，再交给 jsQR 真正扫码，逐条和源配置比对。任何一环错位都会解出乱码点阵、扫码直接失败。

## 四、部署 GitHub Pages

推仓库根目录（`index.html` 就在根上）：

1. Settings → Pages → Source: `Deploy from a branch`
2. Branch: `main`，目录 `/ (root)` → Save
3. 等待几分钟，访问 `https://<账号>.github.io/<仓库>/`

`.nojekyll` 已经放好，防止下划线开头的文件被 Jekyll 吞掉。

只提交这些：

```
index.html  .nojekyll  .gitignore  assets/**  tools/**（不含 local 文件）
```

`tools/channels.local.json`、`tools/secret.local.json`、`tools/node_modules/` 已在 `.gitignore` 里。

## 五、防护做到什么程度

**网络层**

- 二维码没有任何图片文件，也没有接口返回它——点按钮时网络面板是空的（除了一条噪音 404）
- 也就是说：抓包拿不到链接，也没有可热链的图片地址

**源码层**

- 仓库里只有 AES-256-GCM 密文，明文链接在构建期就被编码成二维码点阵再加密
- 运行时解密出来的是**点阵位图**，不是字符串——攻击者拿到解密的中间结果，仍然得把点阵渲染出来再扫
- 密钥拆成 4 段，各自 XOR 掩码后乱序存放，没有单一变量握着完整密钥
- PBKDF2-SHA256 21 万轮，每个网盘独立盐值

**运行时层**

- `toDataURL` / `toBlob` / `getImageData` / `convertToBlob` 全部禁用，脚本导出画布直接抛异常
- 右键菜单、选中、拖拽、F12、Ctrl+Shift+I/J/C、Ctrl+U、Ctrl+S 全部拦截
- 点按钮时才跑 `debugger` 计时陷阱：调试器真的挂着会暂停，耗时立刻暴露 → 锁定整页；无调试器时该语句是空操作，实测 0.000 ms，阈值 250 ms 留足余量
- 锁定即销毁内存里的密钥 + 擦画布，之后所有交互失效
- `isTrusted` 校验：脚本模拟点击（`element.click()`）不触发
- 页面失焦 / 切标签 / 60 秒后自动擦除二维码
- 禁止被 iframe 嵌套
- CSP 锁死：只允许同源脚本与样式，禁内联、禁 eval、禁外部资源

**说明白一件事**

静态托管意味着密文和解密逻辑都公开在同一个仓库里，谁都下载得到——密码学上这层是"提高成本"，不是"不可能"。真正撑住的是运行时那几道：想批量抓，脚本导不出画布、模拟点击无效、点了按钮调试器会停在那里；而一个愿意手动开页面、亲眼看、亲手扫的人，跟正常用户没有区别——他能扫到，就本该能扫到。

如果链接属于**必须保密、连手动扫码都不该外泄**的东西，静态托管不够用：得换成服务端按会话签发（Cloudflare Worker / 任意后端），二维码每次不同、一次性、带过期。

**开关**

`assets/app.js` 顶部 `const STRICT = true;` 改成 `false`，只关掉 `debugger` 陷阱这一道，其余静默防护保留。

**关于控制台探测（已移除）**

早期版本用 `/x/` 正则的 `toString` 陷阱探测控制台，原理是"控制台打开才会 render 这条消息"。实测在 Chrome 157 上，控制台**关着**也会在 1.4 秒时触发 `toString`——真实无头绪的访客会被锁页。已整段删除：宁可少一层探测，不能对正常用户误伤。
