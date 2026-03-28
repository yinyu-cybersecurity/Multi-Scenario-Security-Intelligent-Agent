# Insecure Source Code Management - 不安全源代码管理

[SEARCH_KEYWORDS]
漏洞类型: Insecure Source Code Management SCM 源代码泄露 Git泄露 SVN泄露
攻击类型: Source Code Leak Information Disclosure Credential Leak
关键词: .git .svn .hg .bzr Mercurial Bazaar Subversion repository
技术: Git Dump SVN Dump Directory Listing Configuration Exposure
路径: /.git/ /.svn/ /.hg/ /.bzr/

[CONTENT]

## 不安全源代码管理概述

不安全源代码管理(SCM)可能导致Web应用程序和服务中的严重漏洞。开发人员依赖Git和Subversion(SVN)等SCM系统管理源代码版本。然而，将.git和.svn文件夹暴露在互联网上可能带来重大风险。

## 风险类型

### 源代码泄露

攻击者可以下载整个源代码仓库，获取应用程序逻辑。

### 敏感信息暴露

代码库中可能包含嵌入的秘密、配置文件和凭证。

### 提交历史暴露

攻击者可以查看过去更改，揭示可能之前暴露后缓解的敏感信息。

## 检测方法

### 手动检查

检查常见SCM路径URL：
- Git: `http://target.com/.git/`
- SVN: `http://target.com/.svn/`
- Mercurial: `http://target.com/.hg/`
- Bazaar: `http://target.com/.bzr/`

### 自动化工具

nmap扫描：

```powershell
nmap -sV --script "http-git" -p 80,443 target.com
```

## 绕过技术

### .htaccess绕过

NGINX规则返回403而非404：

```ps1
location /.git {
  deny all;
}
```

即使无法列出.git文件夹内容，Git数据提取仍可进行。

## 利用技术

### Git

1. 下载.git目录
2. 使用git命令恢复文件
3. 分析源代码和配置

### SVN

1. 访问.svn/entries
2. 下载工作副本数据
3. 提取敏感信息

## 防护措施

1. 删除生产环境中的SCM文件夹
2. 配置Web服务器阻止访问SCM路径
3. 使用.gitignore等文件确保敏感文件不被提交

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Source Code Management/README.md