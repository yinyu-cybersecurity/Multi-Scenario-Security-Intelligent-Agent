# Exchange攻击

## 1. ProxyLogon (CVE-2021-26855)

```bash
python3 proxylogon.py user:password@target.com
```

## 2. ProxyShell (CVE-2021-34473)

```bash
python3 proxyshell.py user:password@target.com
```

## 3. ProxyToken (CVE-2021-3129)

```
绕过认证
```

## 4. Exchange枚举

```powershell
Get-Mailbox
Get-ADUser
```

## 5. 邮箱访问

```powershell
Export-Mailbox
New-MailboxExportRequest
```

## 6. 后门利用

### WebShell

```
/owa/auth/current/themes/
```

### 恶意规则

```
收件箱规则创建后门
```
