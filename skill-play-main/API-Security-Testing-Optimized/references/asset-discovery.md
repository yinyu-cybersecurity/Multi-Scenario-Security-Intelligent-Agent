# Asset Discovery Guidance

将原始 API 材料转换为紧凑的安全相关清单。

## 目标

识别对安全测试最重要的 API 部分。

## 核心表面

- base URL(s)
- versioning scheme
- routes 或 operations
- methods
- content types
- auth schemes

## 信任边界

- public vs authenticated endpoints
- user vs admin operations
- internal vs external APIs
- service-to-service 或 callback flows
- tenant 或 organization 边界

## 敏感对象

关注以下对象：
- users
- roles
- teams
- organizations
- invoices
- payments
- orders
- files
- secrets
- API keys
- tokens
- audit logs
- exports
- configuration objects

## 高风险操作模式

标记与以下相关的 endpoints 或 mutations：
- create/update/delete user
- role assignment
- permission change
- password reset
- token issue 或 refresh
- export 或 bulk download
- import 或 bulk update
- file upload
- webhook registration
- callback URL configuration
- search 或 filter on sensitive entities
- internal admin dashboards 或 debug endpoints

## REST 提示

优先包含模式的 endpoints：
- `/admin`
- `/internal`
- `/users`
- `/roles`
- `/permissions`
- `/export`
- `/import`
- `/search`
- `/upload`
- `/files`
- `/billing`
- `/settings`
- `/token`
- `/auth`
- `/debug`

同时注意：
- bulk 操作
- object IDs in path 或 query
- 同一资源上隐藏的替代方法
- 不一致的版本化 endpoints

## GraphQL 提示

优先：
- 变更 roles、permissions 或 state 的 mutations
- 暴露嵌套对象遍历的 fields
- admin-only resolvers
- schema introspection 暴露
- 带敏感链接数据的宽对象图
- 可能意外扩展访问的 connection 或 pagination 模式

## 资产摘要格式

优先简洁输出：

```
- Base URLs:
- API type:
- Auth schemes:
- Roles observed or assumed:
- Sensitive objects:
- High-risk operations:
- Trust boundaries:
- Unknown areas:
```

## 优先级规则

当表面较大时，优先深度在：
1. auth 和 role 变更
2. user 和 tenant 数据
3. export/import 和 bulk 操作
4. file 和 callback 流程
5. 金融或行政操作

不要在低风险的只读 metadata endpoints 上浪费空间，除非它们支持更广泛的滥用路径。
