# REST Guidance

当 API 是 REST 风格或面向资源时使用。

## 关注领域

- object identifiers in paths and query strings
- method confusion across the same resource
- alternate versions exposing weaker controls
- bulk read and bulk write operations
- export and import endpoints
- callback URL configuration
- file upload and file retrieval
- verbose errors and debug metadata

## 常见风险信号

- `GET /resource/{id}` with predictable IDs
- `PUT` or `PATCH` routes that accept role, tenant, or owner fields
- undocumented admin or support routes
- query parameters affecting filtering, sorting, or joins on sensitive objects
- separate internal and public route families with inconsistent auth
- data export endpoints returning broad records with limited user context

## 推荐分组

按对象家族或工作流分组 endpoints，而非单独列出每个路由。

示例分组：
- user administration
- billing and invoices
- file operations
- reporting and exports
- organization or tenant management
- authentication and sessions
- API key and token management
- administrative operations
- data import and bulk updates
- search and filter operations

## 特别关注

### 对象引用

- 路径中的数字 ID（可预测？）
- UUID vs 序列号
- 嵌套资源路径 `/users/{id}/orders/{order_id}`

### 方法混淆

- 同资源不同方法（GET vs PUT vs DELETE）
- PUT 接受不应该能修改的字段（role, tenant_id）

### 版本差异

- `/v1/` vs `/v2/` 的安全控制是否一致
- 旧版本是否暴露更多功能

### Admin 接口

- `/admin/` 家族
- `/internal/` 家族
- `/debug/` 或 `/manage/`

### 文件操作

- `/upload/`
- `/import/`
- `/export/`
- `/download/`

### 敏感查询

- 影响 join 的查询参数
- 排序和过滤敏感对象
- 分页参数的访问控制
