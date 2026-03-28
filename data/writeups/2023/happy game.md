---
tags: [Java反序列化, gRPC, CommonsCollections, ProcessBuilder, RCE]
---

# happy game

开放了grpc端口，可以使用postman连接。开放了两个服务：

```
service Greeter {
rpc SayHello(helloworld .HelloRequest) returns (helloworld .HelloReply) {} rpc ProcessMsg(helloworld .Request) returns (helloworld .Reply) {}
}
```

其中ProcessMsg ，可以接受序列化数据。测试发现存在cc5的链子 ，但是打 runtime .exec 没成功 ，换成用 ProcessBuilder 弹shell成功。