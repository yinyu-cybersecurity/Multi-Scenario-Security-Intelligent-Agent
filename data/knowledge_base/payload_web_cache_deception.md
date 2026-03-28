# Web Cache Deception - Web缓存欺骗

[SEARCH_KEYWORDS]
漏洞类型: Web Cache Deception WCD 缓存欺骗 缓存中毒 Cache Poisoning
攻击类型: Information Disclosure Data Leakage Session Hijacking Account Takeover
关键词: cache caching proxy CDN CloudFlare extension path manipulation
技术: Cache Busting Extension Spoofing Path Confusion Unkeyed Input
平台: CloudFlare Nginx Apache Varnish Fastly Akamai

[CONTENT]

## Web缓存欺骗概述

Web缓存欺骗(WCD)是一种安全漏洞，当Web服务器或缓存代理错误解释客户端对Web资源的请求，并缓存了更敏感或私有的资源时发生。

## 攻击原理

攻击示例：诱使登录用户访问 `http://www.example.com/home.php/non-existent.css`

1. 浏览器请求资源 `http://www.example.com/home.php/non-existent.css`
2. 缓存服务器搜索资源，未找到
3. 请求转发到主服务器
4. 主服务器返回 `home.php` 内容
5. 响应经过缓存服务器
6. 缓存服务器识别CSS扩展
7. 缓存服务器缓存此"CSS"文件
8. 攻击者请求相同URL，获取缓存的敏感数据

## 测试技巧

### 路径扩展欺骗

```powershell
https://example.com/app/conversation/.js?test
https://example.com/app/conversation/;.js
https://example.com/home.php/non-existent.css
https://example.com/myaccount/home/malicious.css
```

### 缓存中毒攻击

查找unkeyed输入：

```text
User-Agent
Cookie
X-Forwarded-Host
X-Host
X-Forwarded-Server
X-Forwarded-Scheme
X-Original-URL (Symfony)
X-Rewrite-URL (Symfony)
```

利用示例：

```http
GET /test?buster=123 HTTP/1.1
Host: target.com
X-Forwarded-Host: test"><script>alert(1)</script>
```

## CloudFlare缓存

CloudFlare默认缓存扩展名：

| 类别 | 扩展名 |
|------|--------|
| 图片 | JPG, JPEG, PNG, GIF, ICO, SVG, SVGZ, WEBP, AVIF, BMP, TIF, TIFF |
| 视频 | MP4, WEBM, MKV, AVI, MOV |
| 音频 | MP3, OGG, FLAC, MIDI, MID |
| 文档 | PDF, DOC, DOCX, PPT, PPTX, XLS, XLSX, CSV, EPS |
| 代码 | JS, CSS, EJS, JAR, CLASS |
| 字体 | TTF, OTF, WOFF, WOFF2, EOT |
| 压缩 | ZIP, GZ, BZ2, RAR, TAR, 7Z, ZST |

### Cache Deception Armor

CloudFlare的Cache Deception Armor规则验证URL扩展与返回的Content-Type匹配。

## 实际案例

### PayPal首页WCD

1. 正常访问：`https://www.example.com/myaccount/home/`
2. 打开恶意链接：`https://www.example.com/myaccount/home/malicious.css`
3. 页面显示/home内容，缓存保存
4. 隐私标签访问相同URL
5. 显示缓存的敏感内容

### OpenAI账户接管

1. 攻击者构造 `/api/auth/session` 的.css路径
2. 分发链接
3. 受害者访问合法链接
4. 响应被缓存
5. 攻击者获取JWT凭证

## 工具

- param-miner - Burp缓存中毒扩展

## 参考文档

原始来源: PayloadsAllTheThings/Web Cache Deception/README.md