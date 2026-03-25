# 工具可用性验证清单

本文档记录所有工具的安装方式和检测路径，确保 Dockerfile 与工具文件路径一致。

## 一、pipx 安装的 Python 工具

安装路径: `/root/.local/bin/` 或作为模块安装

| 工具名 | 安装命令 | 检测方式 | 工具文件 |
|--------|----------|----------|----------|
| sqlmap | `pipx install sqlmap` | `shutil.which("sqlmap")` | sqlmap_tool.py |
| fenjing | `pipx install fenjing` | `shutil.which("fenjing")` | fenjing_tool.py |
| flask-unsign | `pipx install flask-unsign` | `shutil.which("flask-unsign")` | flask_unsign_tool.py |
| git-hacker | `pipx install git-hacker` | `shutil.which("githacker")` | git_hacker_tool.py |
| xsser | `pipx install xsser` | `shutil.which("xsser")` | xsser_tool.py |
| impacket | `pipx install impacket` | `shutil.which("secretsdump")` 等 | impacket_tools.py |
| pwntools | `pipx install pwntools` | 模块导入 | (内置使用) |
| ROPgadget | `pipx install ROPgadget` | `shutil.which("ROPgadget")` | (内置使用) |
| CrackMapExec | `pipx install git+...` | `shutil.which("crackmapexec")` | crackmapexec_tool.py |
| BloodHound.py | `pipx install git+...` | `shutil.which("bloodhound-python")` | bloodhound_tool.py |

## 二、Go 安装的工具

安装路径: `/root/go/bin/`

| 工具名 | 安装命令 | 检测方式 | 工具文件 |
|--------|----------|----------|----------|
| nuclei | `go install ...nuclei@latest` | `shutil.which("nuclei")` | nuclei_scanner.py |
| ffuf | `go install ...ffuf@latest` | `shutil.which("ffuf")` | ffuf_tool.py |
| httpx | `go install ...httpx@latest` | `shutil.which("httpx")` | (内置使用) |
| subfinder | `go install ...subfinder@latest` | `shutil.which("subfinder")` | (内置使用) |
| httprobe | `go install ...httprobe@latest` | `shutil.which("httprobe")` | (内置使用) |

## 三、apt 安装的系统工具

| 工具名 | 安装命令 | 检测方式 | 工具文件 |
|--------|----------|----------|----------|
| nmap | `apt-get install nmap` | `shutil.which("nmap")` | nmap_tool.py |
| hydra | `apt-get install hydra` | `shutil.which("hydra")` | hydra_tool.py |

## 四、wget 下载的 Java 工具

| 工具名 | 下载路径 | 检测方式 | 工具文件 |
|--------|----------|----------|----------|
| ysoserial | `/app/thirdparty/ysoserial.jar` | `os.path.exists()` | ysoserial_tool.py |
| JNDIExploit | `/app/thirdparty/JNDIExploit.jar` | `os.path.exists()` | jndi_exploit_tool.py |
| marshalsec | `/app/thirdparty/marshalsec.jar` | `os.path.exists()` | marshalsec_tool.py |

## 五、wget 下载的二进制工具

| 工具名 | 下载路径 | 检测方式 | 工具文件 |
|--------|----------|----------|----------|
| frp | `/opt/frp/frpc` | `Path.exists()` | frp_manager.py |
| fscan | `/usr/local/bin/fscan` | `shutil.which("fscan")` | fscan_tool.py |
| xray | `/usr/local/bin/xray` | `shutil.which("xray")` | xray_scanner.py |
| mimikatz | `/opt/tools/x64/mimikatz.exe` | `os.path.exists()` | mimikatz_tool.py |
| Rubeus | `/opt/tools/windows/Rubeus.exe` | `os.path.exists()` | ad_tools.py |
| PrintSpoofer | `/opt/tools/potato/PrintSpoofer64.exe` | `os.path.exists()` | potato_tool.py |
| SweetPotato | `/opt/tools/potato/SweetPotato.exe` | `os.path.exists()` | potato_tool.py |
| GodPotato | `/opt/tools/potato/GodPotato.exe` | `os.path.exists()` | potato_tool.py |

## 六、git clone 的工具

| 工具名 | Clone 路径 | 检测方式 | 工具文件 |
|--------|------------|----------|----------|
| PetitPotam | `/app/thirdparty/PetitPotam/` | `os.path.exists()` | ad_tools.py |
| phpggc | `/app/thirdparty/phpggc/` | `os.path.exists()` | phpggc_tool.py |
| jwt_tool | `/app/thirdparty/jwt_tool/` | `os.path.exists()` | jwt_tool.py |
| JSFinder | `/app/thirdparty/jsfinder/` | `os.path.exists()` | jsfinder_tool.py |
| ajpshooter | `/app/thirdparty/ajpshooter/` | `os.path.exists()` | ajpshooter_tool.py |
| xxe-injector | `/app/thirdparty/xxe-injector/` | `os.path.exists()` | xxe_injector_tool.py |

## 七、特殊安装的工具

| 工具名 | 安装方式 | 检测方式 | 工具文件 |
|--------|----------|----------|----------|
| Metasploit | msfinstall | `shutil.which("msfconsole")` | metasploit_tool.py |

## 前端工具分类

前端 `/api/tools` 接口返回以下分类：

1. **Impacket工具集** - dacledit, secretsdump, wmiexec, psexec, getnpusers, getuserspns, ntlmrelayx
2. **Web攻击** - sqlmap, ffuf, dirsearch, nuclei, xray, nmap, httpx, subfinder, httprobe
3. **Java反序列化** - ysoserial, jndi-exploit, marshalsec
4. **AD域攻击** - petitpotam, rubeus, bloodhound, crackmapexec, mimikatz
5. **权限提升** - potato, privesc
6. **信息泄露** - jsfinder, git-hacker, xxe-injector, ajp-shooter
7. **会话攻击** - flask-unsign, jwt-tool
8. **密码学** - fenjing
9. **框架工具** - metasploit, metasploit-manager, fscan, hydra
10. **其他工具** - 未分类的工具

## 验证命令

在 Docker 容器内运行：

```bash
# 检查 pipx 安装的工具
ls /root/.local/bin/

# 检查 Go 工具
ls /root/go/bin/

# 检查下载的工具
ls /app/thirdparty/*.jar
ls /opt/tools/windows/
ls /opt/tools/potato/
ls /opt/frp/

# 检查 git clone 的工具
ls /app/thirdparty/
```