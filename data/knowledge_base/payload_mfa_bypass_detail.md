# MFA/2FA Bypass - 多因素认证绕过

[SEARCH_KEYWORDS]
漏洞类型: Authentication Bypass MFA Bypass 2FA Bypass 认证绕过
攻击类型: Authentication Bypass Session Hijacking
关键词: MFA 2FA OTP TOTP SMS Authentication Multi-Factor
技术: Response Manipulation Status Code CSRF Brute Force Force Browsing
绕过方法: Response Manipulation Status Code Code Leakage CSRF

[CONTENT]

## MFA/2FA绕过概述

多因素认证(MFA)要求用户提供两种或以上验证因素。MFA绕过技术利用实现缺陷绕过保护，包括响应操纵、CSRF、暴力破解等方法。

## 绕过技术

### 1. 响应操纵 (Response Manipulation)

响应中`"success":false`改为`"success":true`

### 2. 状态码操纵 (Status Code Manipulation)

将4xx状态码改为200 OK

### 3. 2FA码响应泄露 (2FA Code Leakage in Response)

检查2FA触发请求的响应，查找泄露的验证码

### 4. JS文件分析 (JS File Analysis)

检查JS文件是否包含2FA相关信息

### 5. 2FA码重用 (2FA Code Reusability)

同一验证码可多次使用

### 6. 缺少暴力破解保护 (Lack of Brute-Force Protection)

可以暴力破解任意长度2FA验证码

### 7. 缺少2FA码完整性验证 (Missing 2FA Code Integrity Validation)

任意用户账户的验证码可用于绕过2FA

### 8. CSRF禁用2FA (CSRF on 2FA Disabling)

禁用2FA无CSRF保护，无认证确认

### 9. 密码重置禁用2FA (Password Reset Disable 2FA)

密码更改/邮箱更改时2FA被禁用

### 10. 备用码滥用 (Backup Code Abuse)

利用备用码功能绕过2FA

### 11. 点击劫持 (Clickjacking on 2FA Disabling Page)

iframe嵌入2FA禁用页面，社工诱导用户禁用

### 12. 会话未过期 (Enabling 2FA doesn't expire Previously active Sessions)

启用2FA后，已劫持的会话仍然有效

### 13. 强制浏览绕过 (Bypass 2FA by Force Browsing)

2FA禁用时登录重定向到`/my-account`
启用2FA时尝试将`/2fa/verify`替换为`/my-account`

### 14. Null/000000绕过 (Bypass 2FA with null or 000000)

输入验证码`000000`或`null`

### 15. 数组绕过 (Bypass 2FA with array)

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

- [ ] 响应/状态码操纵
- [ ] 验证码响应泄露
- [ ] JS文件分析
- [ ] 验证码重用测试
- [ ] 暴力破解测试
- [ ] 跨用户验证码测试
- [ ] CSRF禁用测试
- [ ] 密码重置影响测试
- [ ] 备用码功能测试
- [ ] 点击劫持测试
- [ ] 会话过期测试
- [ ] 强制浏览测试
- [ ] 特殊值测试(null/000000)
- [ ] 数组注入测试

## 参考文档

原始来源: PayloadsAllTheThings/Account Takeover/mfa-bypass.md