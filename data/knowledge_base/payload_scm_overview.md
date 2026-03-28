# Source Code Management Leak - 源码管理信息泄露

[SEARCH_KEYWORDS]
漏洞类型: Information Disclosure Source Code Leak 敏感信息泄露
攻击类型: Source Code Exposure Configuration Leak
关键词: Git SVN Mercurial Bazaar .git .svn .hg .bzr 版本控制
技术: SCM Folder Exposure Repository Download Credential Exposure
工具: git-dumper svn-extractor dvcs-ripper
路径: .git .svn .hg .bzr

[CONTENT]

## 源码管理信息泄露概述

不安全的源码管理(SCM)配置可能导致`.git`、`.svn`等文件夹暴露在生产环境中，攻击者可以下载整个源代码仓库，获取应用逻辑、敏感信息和凭据。

## 检测方法

手动检查常见SCM路径:
- Git: `http://target.com/.git/`
- SVN: `http://target.com/.svn/`
- Mercurial: `http://target.com/.hg/`
- Bazaar: `http://target.com/.bzr/`

## 风险影响

- **源代码泄露**: 获取完整应用源码和业务逻辑
- **敏感信息暴露**: 嵌入的密钥、配置文件、凭据
- **提交历史暴露**: 查看历史变更中的敏感信息

## 利用技术

### 绕过访问限制

NGINX规则返回403而非404:
```nginx
location /.git {
  deny all;
}
```

即使无法列出`.git`目录内容，只要能读取文件，数据提取仍然可行。

### 各版本控制系统

| 系统 | 目录 | 详细文档 |
|------|------|----------|
| Git | .git | Git Source Code Leak |
| SVN | .svn | SVN Source Code Leak |
| Mercurial | .hg | Mercurial Source Code Leak |
| Bazaar | .bzr | Bazaar Source Code Leak |

## 防护建议

1. 删除生产环境中的SCM目录
2. 配置Web服务器阻止访问隐藏目录
3. 使用`.gitignore`排除敏感文件
4. 不要在代码中硬编码凭据

## 练习靶场

- [Root Me - Insecure Code Management](https://www.root-me.org/fr/Challenges/Web-Serveur/Insecure-Code-Management)

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Source Code Management/README.md