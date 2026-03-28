# Source Code Leak Mercurial - Mercurial源码泄露

[SEARCH_KEYWORDS]
漏洞类型: Source Code Leak Mercurial hg 源码泄露 版本控制泄露
攻击类型: Information Disclosure Source Code Access
关键词: Mercurial hg .hg DVCS version control repository
技术: rip-hg hg extraction repository dump
工具: rip-hg.pl dvcs-ripper

[CONTENT]

## Mercurial源码泄露概述

Mercurial(又称hg，来自水银的化学符号)是一个分布式版本控制系统(DVCS)，以速度、简单和处理大型代码库的能力著称。当.hg目录暴露在Web服务器上时，攻击者可以恢复整个源代码仓库。

## 利用工具

### rip-hg.pl

使用dvcs-ripper工具集:

```powershell
docker run --rm -it -v /path/to/host/work:/work:rw k0st/alpine-dvcs-ripper rip-hg.pl -v -u http://target.com/.hg/
```

## 关键文件路径

| 文件 | 描述 |
|------|------|
| `.hg/` | Mercurial仓库目录 |
| `.hg/store/` | 文件存储目录 |
| `.hg/00manifest.i` | 清单索引 |
| `.hg/00changelog.i` | 变更日志索引 |
| `.hg/hgrc` | 仓库配置文件 |

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Source Code Management/Mercurial.md