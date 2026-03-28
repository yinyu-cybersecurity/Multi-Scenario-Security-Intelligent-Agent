# Client Side Path Traversal - 客户端路径遍历

[SEARCH_KEYWORDS]
漏洞类型: Client Side Path Traversal CSPT 客户端路径遍历 On-site Request Forgery
攻击类型: CSRF XSS Path Manipulation Authentication Bypass
关键词: CSPT fetch path traversal normalization ../ client side
技术: CSPT to XSS CSPT to CSRF Path Normalization Cookie Inclusion
CVE: CVE-2023-45316 CVE-2023-6458 CVE-2023-5123

[CONTENT]

## 客户端路径遍历概述

客户端路径遍历(CSPT)利用客户端使用fetch向URL发送请求的能力，其中可以注入多个"../"字符。规范化后，这些字符将请求重定向到不同URL。由于每个请求都从应用程序前端发起，浏览器自动包含cookie和其他认证机制。

## CSPT to XSS

### 攻击流程

1. 页面`https://example.com/static/cms/news.html`接受`newsitemid`参数
2. 获取`https://example.com/newitems/<newsitemid>`内容
3. 发现`https://example.com/pricing/default.js`中通过`cb`参数存在文本注入
4. 最终payload：

```ps1
https://example.com/static/cms/news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//
```

## CSPT to CSRF

CSPT重定向合法HTTP请求，允许前端添加API调用所需的token。

### CSPT vs CSRF对比

| 特性 | CSRF | CSPT2CSRF |
|------|------|-----------|
| POST CSRF | ✓ | ✓ |
| 可控制body | ✓ | ✗ |
| 反CSRF token | ✗ | ✓ |
| SameSite=Lax | ✗ | ✓ |
| GET/PATCH/PUT/DELETE | ✗ | ✓ |
| 1-click CSRF | ✗ | ✓ |

### 真实案例

**CVE-2023-45316 (Mattermost)**：

```ps1
/<team>/channels/channelname?telem_action=under_control&forceRHSOpen&telem_run_id=../../../../../../api/v4/caches/invalidate
```

**CSPT2CSRF示例**：

```ps1
https://example.com/signup/invite?email=foo%40bar.com&inviteCode=123456789/../../../cards/123e4567-e89b-42d3-a456-556642440000/cancel?a=
```

## 工具

- CSPTBurpExtension - 发现和利用CSPT的Burp扩展
- CSPTPlayground - CSPT学习环境

## 发现方法

1. 查找fetch调用
2. 识别用户可控的URL参数
3. 测试`../`序列注入
4. 验证路径规范化后的目标

## 防护措施

1. 正确编码URL路径
2. 验证重定向目标
3. 使用绝对URL
4. 实施CSP策略

## 参考文档

原始来源: PayloadsAllTheThings/Client Side Path Traversal/README.md