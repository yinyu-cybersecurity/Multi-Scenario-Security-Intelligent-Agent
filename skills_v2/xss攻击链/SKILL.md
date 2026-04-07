---
name: xss攻击链
description: Use when encountering xss攻击思维链 - 反射/存储/dom型、waf绕过、利用技巧
---

# XSS攻击链

## Info

- **Domain**: web
- **Tags**: web, xss

# XSS攻击思维链

```
类型判断 → 反射型(URL参数)/存储型(表单存储)/DOM型(前端渲染)
      ↓
绕过过滤 → 标签/事件/编码/协议
      ↓
利用执行 → Cookie窃取/钓鱼/键盘记录/BeEF
```

---

## 类型判断

| 类型 | 特征 | 触发点 |
|------|------|--------|
| 反射型 | URL参数直接输出 | 搜索页/错误页 |
| 存储型 | 数据存数据库后输出 | 评论/用户资料/帖子 |
| DOM型 | 前端JS动态渲染 | location.hash/innerHTML |

---

## 绕过技巧

**标签替代**:
- `<script>` → `<img/svg/iframe/video/audio/details>`
- `<on事件>` → `onerror/onload/onfocus/onmouseover`

**编码绕过**:
- HTML实体: `&#x3c;script&#x3e;`
- Unicode: `\u003cscript\u003e`
- URL编码: `%3Cscript%3E`
- Base64: `<a href="data:text/html;base64,...">`

**特殊构造**:
- 大小写混合: `<ScRiPt>`
- 插入符号: `<scr<script>ipt>`
- 利用事件: `<img src=x onerror=alert(1)>`
- 利用伪协议: `<a href="javascript:alert(1)">`

---

## CSP绕过

| CSP策略 | 绕过方法 |
|---------|----------|
| script-src self | JSONP回调/重定向 |
| default-src self | iframe srcdoc |
| 无unsafe-inline | DOM XSS/事件处理器 |
| 无unsafe-eval | DOM clobbering |

---

## 利用方式

**Cookie窃取**: document.cookie发送到攻击者
**会话劫持**: 获取session后直接登录
**键盘记录**: 监听onkeypress事件
**钓鱼**: 伪造登录框
**BeEF**: 加载钩子脚本控制浏览器

---

## XSS工具

- **XSStrike**: 自动化扫描
- **BeEF**: 浏览器控制框架
- **XSStriker**: WAF绕过测试