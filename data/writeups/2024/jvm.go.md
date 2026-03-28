---
tags: [Golang, JVM, 内存破坏, 原生方法漏洞, RCE]
---

# jvm.go

漏洞点猜测位于jvm-go/native/java/io/FileDescriptor动态了set方法为

```
func  set(frame  *rtda .Frame)  {
frame .PushLong(0 )
}
```

而jvm原方法会去清理指针