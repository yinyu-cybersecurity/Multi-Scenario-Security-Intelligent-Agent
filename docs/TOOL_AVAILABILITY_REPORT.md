# 工具可用性检查报告

## 问题分类

### 1. Dockerfile根本没安装的工具
| 工具 | 状态 | 解决方案 |
|------|------|----------|
| `hydra` | 未安装 | 添加 `apt-get install hydra` 或删除 |
| `metasploit` | 未安装 | 太大，建议删除工具封装 |
| `xsser` | 未安装 | 添加 `pipx install xsser` 或删除 |
| `rubeus` | 未安装 | 删除工具封装 (Windows工具，需要在目标机器上运行) |
| `dacledit` | 未安装 | 删除工具封装 (impacket内置) |
| `git-hacker` | 未安装 | 添加 `pipx install git-hacker` |
| `xxe-injector` | 未安装 | 删除工具封装 |

### 2. 路径不匹配
| 工具 | Dockerfile路径 | check_available检查路径 | 问题 |
|------|----------------|------------------------|------|
| `jndi-exploit` | `/app/thirdparty/JNDIExploit.jar` | `jndi-exploit.jar` (小写) | 文件名不一致 |
| `marshalsec` | `/app/thirdparty/marshalsec/` (源码) | `marshalsec.jar` | 未编译成jar |
| `petitpotam` | `/app/thirdparty/PetitPotam/` | `/opt/PetitPotam/` | 路径不匹配 |
| `mimikatz` | `/opt/tools/mimikatz/` | 检查了正确路径 | 应该正常 |

### 3. pipx安装但检查方式错误
| 工具 | 安装方式 | 检查方式 | 问题 |
|------|----------|----------|------|
| `flask-unsign` | pipx安装 | `import flask_unsign` | pipx是独立环境，无法import |

### 4. 已安装但可能路径问题
| 工具 | 安装位置 | 检查方式 |
|------|----------|----------|
| `ffuf` | `/root/go/bin/ffuf` | `shutil.which("ffuf")` |
| `jsfinder` | 未安装 | 需要检查 |

## 推荐修复方案

### 方案A: 修复Dockerfile和工具检查路径
1. 添加缺失工具的安装
2. 修复路径不匹配问题
3. 编译marshalsec

### 方案B: 删除不可用工具封装
1. 删除 `hydra`, `metasploit`, `xsser`, `rubeus`, `dacledit`, `xxe-injector` 等工具封装
2. 这些工具要么太大，要么需要在目标机器上运行
3. 保持框架精简

### 建议采用方案B
原因：
1. Metasploit 镜像太大 (1GB+)
2. Rubeus/dacledit 是Windows工具，需要在目标机器上运行，不适合在框架内封装
3. XXE-Injector 等工具维护不活跃
4. hydra 等工具可用其他方式替代