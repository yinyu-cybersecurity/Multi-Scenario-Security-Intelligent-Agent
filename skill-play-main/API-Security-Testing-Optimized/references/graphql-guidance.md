# GraphQL Guidance

分析 GraphQL API 时使用。

## 关注领域

### 字段级授权

- resolver 是否正确检查权限
- 嵌套查询是否泄露数据
- 是否缺少 admin-only 字段

### 嵌套遍历

- `type User { friends: [User!]! }` 可导致递归查询
- `type Post { author: User }` 允许遍历
- 是否限制遍历深度

### Resolver 边界

- 一个 resolver 是否调用另一个 service
- 是否存在 SSRF 风险
- 是否有命令注入点

### Mutation 滥用

- 未经授权的状态变更
- 条件 mutation（如 admin-only mutation）
- 批量 mutation 导致的问题

### Introspection 暴露

- 是否禁用 introspection
- 是否暴露敏感字段
- Schema 文档是否包含敏感信息

## 常见风险信号

- ` IntrospectionQuery` 可访问
- 缺少 query 复杂度限制
- 缺少 query 深度限制
- 缺少字段权限检查
- mutation 接受任意输入
- 嵌套查询无限制

## 测试重点

### 1. 枚举攻击

```graphql
# 枚举所有用户
query {
  users {
    id
    username
    email
  }
}
```

### 2. 嵌套遍历

```graphql
# 递归遍历 friendships
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          id
        }
      }
    }
  }
}
```

### 3. 权限绕过

```graphql
# 尝试 admin 字段
query {
  user(id: 1) {
    isAdmin
    role
  }
}
```

### 4. mutation 滥用

```graphql
# 未经授权的 mutation
mutation {
  updateUser(id: 1, role: "admin") {
    id
    role
  }
}
```

## 防护检查

- [ ] 是否限制查询复杂度
- [ ] 是否限制查询深度
- [ ] 是否禁用 introspection
- [ ] resolver 是否有权限检查
- [ ] 是否过滤敏感字段
