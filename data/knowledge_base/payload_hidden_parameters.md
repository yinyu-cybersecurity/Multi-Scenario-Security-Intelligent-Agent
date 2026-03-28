# Hidden Parameters - 隐藏参数发现

[SEARCH_KEYWORDS]
漏洞类型: Hidden Parameters 隐藏参数 Undocumented Parameters Parameter Discovery
攻击类型: Information Disclosure Access Control Bypass Logic Bypass
关键词: parameter hidden undocumented fuzzing discovery bruteforce
技术: Parameter Bruteforce Wayback Machine JS Analysis Old Parameters
工具: param-miner Arjun x8 waybackurls ParamSpider

[CONTENT]

## 隐藏参数概述

Web应用程序通常具有未在用户界面中公开的隐藏或未记录参数。模糊测试可以帮助发现这些参数，它们可能容易受到各种攻击。

## 发现技术

### 参数爆破

使用常用参数字典发送请求，观察后端异常行为：

```ps1
x8 -u "https://example.com/" -w <wordlist>
x8 -u "https://example.com/" -X POST -w <wordlist>
```

### 字典资源

- Arjun/large.txt
- Arjun/medium.txt
- Arjun/small.txt
- samlists/sam-cc-parameters-lowercase-all.txt
- samlists/sam-cc-parameters-mixedcase-all.txt

### 旧参数发现

探索目标URL查找旧参数：

1. **Wayback Machine**
   - 访问 http://web.archive.org/
   - 查找历史版本中的参数

2. **JS文件分析**
   - 检查JavaScript文件
   - 发现未使用的参数

## 工具

### param-miner (Burp扩展)

识别隐藏、未链接参数的Burp扩展。

### Arjun

HTTP参数发现套件：

```ps1
arjun -u https://example.com
```

### x8

隐藏参数发现套件：

```ps1
x8 -u "https://example.com/" -w wordlist.txt
```

### waybackurls

获取Wayback Machine知道的所有URL：

```ps1
waybackurls example.com
```

### ParamSpider

从Web Archives挖掘URL：

```ps1
python3 paramspider.py --domain example.com
```

## 测试流程

1. 收集目标URL
2. 使用工具发现隐藏参数
3. 测试每个参数的安全性
4. 检查逻辑漏洞、注入点等

## 参考文档

原始来源: PayloadsAllTheThings/Hidden Parameters/README.md