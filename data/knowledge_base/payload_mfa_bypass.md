# MFA Bypass - 多因素认证绕过

[SEARCH_KEYWORDS]
漏洞类型: MFA Bypass 2FA Bypass Two-Factor Authentication 多因素认证绕过
攻击类型: Authentication Bypass Session Hijacking Account Takeover
关键词: MFA 2FA OTP TOTP SMS bypass authentication code
技术: Response Manipulation Status Code Brute Force CSRF Session Reuse
绕过方法: null 000000 array force browsing backup code

[CONTENT]

## MFA绕过概述

多因素认证(MFA)绕过是攻击者用来规避MFA保护的技术。包括利用MFA实现弱点、拦截认证令牌、利用会话漏洞等。

## 绕过技术

### 响应操纵

如果响应包含`"success":false`，修改为`"success":true`

### 状态码操纵

如果状态码是**4xx**，尝试改为**200 OK**

### 响应中泄露2FA代码

检查触发2FA代码请求的响应，查看是否泄露代码

### JS文件分析

某些JS文件可能包含2FA代码信息

### 2FA代码可重用

同一代码可多次使用

### 缺乏暴力破解保护

可以暴力破解任意长度的2FA代码

### 缺少代码完整性验证

任何用户的2FA代码都可用于绕过

### 禁用2FA的CSRF

禁用2FA没有CSRF保护，也没有认证确认

### 密码重置禁用2FA

密码更改/邮箱更改时2FA被禁用

### 备份代码滥用

使用上述技术绕过备份代码以移除/重置2FA限制

### 2FA禁用页面点击劫持

用iframe嵌入2FA禁用页面，诱导受害者禁用2FA

### 启用2FA不使先前活跃会话过期

如果会话已被劫持且存在会话超时漏洞

### 强制浏览绕过

如果禁用2FA时应用重定向到`/my-account`，尝试在启用2FA时用`/my-account`替换`/2fa/verify`

### 使用null或000000绕过

```text
输入代码: 000000
输入代码: null
```

### 使用数组绕过

```json
{
    "otp":[
        "1234",
        "1111",
        "1337",
        "2222",
        "3333",
        "4444",
        "5555"
    ]
}
```

## 测试清单

| 测试项 | 说明 |
|--------|------|
| 响应操纵 | 修改success字段 |
| 状态码操纵 | 修改HTTP状态码 |
| 代码泄露 | 检查响应中是否包含代码 |
| 代码重用 | 测试代码是否可多次使用 |
| 暴力破解 | 测试是否有速率限制 |
| 跨用户代码 | 测试其他用户的代码是否有效 |
| CSRF禁用 | 测试禁用功能是否有CSRF保护 |

## 参考文档

原始来源: PayloadsAllTheThings/Account Takeover/mfa-bypass.md