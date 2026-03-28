# Regular Expression - 正则表达式拒绝服务(ReDoS)

[SEARCH_KEYWORDS]
漏洞类型: ReDoS Regular Expression Denial of Service 正则表达式拒绝服务
攻击类型: Denial of Service DoS Resource Exhaustion CPU Exhaustion
关键词: regex regular expression pattern backtrack catastrophic backtracking
技术: Evil Regex Nested Quantifiers Alternation Overlap Backtracking
函数: preg_match regex.test re.search RegExp match

[CONTENT]

## ReDoS概述

正则表达式拒绝服务(ReDoS)是一种攻击，利用某些正则表达式处理时间极长的特点，导致应用程序或服务无响应或崩溃。

## Evil Regex特征

危险正则表达式包含：

1. **分组与重复**
2. **重复组内部**：
   - 重复
   - 重叠的交替

### 危险模式示例

```regex
(a+)+
([a-zA-Z]+)*
(a|aa)+
(a|a?)+
(.*a){x}  # x > 10
```

### 触发Payload

```powershell
aaaaaaaaaaaaaaaaaaaa!
```

20个'a'后跟'!'，正则引擎尝试所有可能的分组方式后最终失败，导致回溯爆炸。

## 回溯限制

回溯发生在正则引擎遇到不匹配时，返回前一位置尝试其他路径。

### PHP PCRE配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| pcre.backtrack_limit | 1000000 | PHP < 5.3.7 为 100000 |
| pcre.recursion_limit | 100000 | - |
| pcre.jit | 1 | - |

### PHP利用示例

```php
$pattern = '/(a+)+$/';
$subject = str_repeat('a', 1000) . 'b';

if (preg_match($pattern, $subject)) {
    echo "Match found";
} else {
    echo "No match";
}
```

超过100000次递归会导致ReDoS，`preg_match`返回false。

## 攻击场景

### 输入验证

```php
// 危险的正则验证
$email_regex = /^([a-zA-Z0-9])+([a-zA-Z0-9\._-])*@([a-zA-Z0-9_-])+([a-zA-Z0-9\._-]+)+$/;
// 攻击输入：超长字符串
```

### 搜索功能

```javascript
// 危险的搜索正则
const pattern = /(a+)+$/;
// 攻击输入：大量'a'字符
```

## 防护措施

1. **避免危险模式**：不使用嵌套量词和重叠交替
2. **设置回溯限制**：`pcre.backtrack_limit`
3. **使用原子组**：`(?>...)`
4. **输入长度限制**
5. **超时机制**

## 工具

- redos-detector - ReDoS检测CLI和库
- regexploit - 发现ReDoS漏洞
- redos-checker - 在线ReDoS检查器

## 参考文档

原始来源: PayloadsAllTheThings/Regular Expression/README.md