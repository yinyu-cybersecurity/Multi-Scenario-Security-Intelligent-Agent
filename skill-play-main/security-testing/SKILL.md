# Payloader Skill - 渗透测试辅助平台

## 概述

本skill提供完整的渗透测试payload知识库、工具命令和攻击链模板，供AI-Agent学习和使用。

## 目录结构

```
payloader/
├── SKILL.md                              # 本文件 - 入口与索引
├── data/
│   ├── web/                             # Web应用攻防
│   │   ├── sqli/                       # SQL注入
│   │   │   ├── mysql.md                 # MySQL注入
│   │   │   ├── mssql.md               # MSSQL注入
│   │   │   ├── oracle.md              # Oracle注入
│   │   │   ├── postgresql.md          # PostgreSQL注入
│   │   │   ├── mongodb.md             # MongoDB注入
│   │   │   ├── redis.md               # Redis注入
│   │   │   ├── sqlite.md              # SQLite注入
│   │   │   ├── blind.md              # 盲注技术
│   │   │   ├── time-blind.md          # 时间盲注
│   │   │   ├── error-based.md         # 报错注入
│   │   │   ├── second-order.md        # 二阶注入
│   │   │   ├── union.md              # 联合查询注入
│   │   │   ├── stacked.md            # 堆叠查询注入
│   │   │   ├── waf-bypass.md          # SQL注入WAF绕过
│   │   │   └── attack-chain.md        # SQL注入攻击链
│   │   ├── xss/                        # XSS跨站脚本
│   │   │   ├── xss-detail.md           # XSS详细分类
│   │   │   ├── waf-bypass.md          # XSS WAF绕过
│   │   │   └── attack-chain.md        # XSS攻击链
│   │   ├── ssrf/                       # SSRF服务端请求伪造
│   │   │   ├── ssrf-detail.md         # SSRF详细分类
│   │   │   ├── waf-bypass.md          # SSRF WAF绕过
│   │   │   └── attack-chain.md        # SSRF攻击链
│   │   ├── rce/                        # RCE远程代码执行
│   │   │   ├── rce-detail.md          # RCE详细分类
│   │   │   ├── waf-bypass.md          # RCE WAF绕过
│   │   │   └── attack-chain.md        # RCE攻击链
│   │   ├── lfi/                        # LFI文件包含
│   │   │   ├── lfi-detail.md         # LFI详细分类
│   │   │   ├── waf-bypass.md          # LFI WAF绕过
│   │   │   └── attack-chain.md        # LFI攻击链
│   │   ├── xxe/                        # XXE实体注入
│   │   │   ├── waf-bypass.md          # XXE WAF绕过
│   │   │   └── attack-chain.md        # XXE攻击链
│   │   ├── ssti/                       # SSTI模板注入
│   │   │   ├── ssti-detail.md        # SSTI详细分类
│   │   │   ├── waf-bypass.md          # SSTI WAF绕过
│   │   │   └── attack-chain.md        # SSTI攻击链
│   │   ├── csrf.md                     # CSRF跨站请求伪造
│   │   ├── auth.md                     # 认证漏洞
│   │   ├── auth-detail.md            # 认证漏洞详细
│   │   ├── file-vulns.md              # 文件漏洞
│   │   ├── cache-cdn.md               # 缓存与CDN安全
│   │   ├── cache-cdn-detail.md       # 缓存与CDN详细
│   │   ├── smuggling.md               # HTTP请求走私
│   │   ├── redirect.md                 # 开放重定向
│   │   ├── clickjacking.md           # 点击劫持
│   │   ├── clickjacking-detail.md    # 点击劫持详细
│   │   ├── biz-logic.md              # 业务逻辑漏洞
│   │   ├── biz-logic-detail.md       # 业务逻辑详细
│   │   ├── jwt.md                    # JWT安全
│   │   ├── jwt-detail.md            # JWT详细
│   │   ├── supply-chain.md           # 供应链攻击
│   │   ├── prototype-pollution.md    # 原型链污染
│   │   ├── cloud.md                  # 云安全
│   │   ├── cloud-detail.md          # 云安全详细
│   │   ├── websocket.md              # WebSocket安全
│   │   ├── ai-security.md            # AI安全
│   │   ├── api.md                    # API安全
│   │   ├── api-detail.md            # API详细
│   │   ├── framework.md               # 框架漏洞
│   │   └── framework-detail.md       # 框架漏洞详细
│   ├── intranet/                      # 内网渗透
│   │   ├── recon/                    # 信息收集
│   │   │   └── intranet-detail.md   # 内网渗透详细
│   │   ├── cred theft/                # 凭证窃取
│   │   │   └── credential-theft-detail.md # 凭证窃取详细
│   │   ├── lateral/                  # 横向移动
│   │   │   └── lateral-detail.md    # 横向移动详细
│   │   ├── privesc/                  # 权限提升
│   │   │   └── privesc-detail.md    # 权限提升详细
│   │   ├── persistence/               # 权限维持
│   │   ├── tunnel/                   # 隧道代理
│   │   │   └── tunnel-detail.md     # 隧道代理详细
│   │   ├── ad-attack/                 # 域渗透攻击
│   │   │   └── ad-attack-detail.md  # AD域渗透详细
│   │   ├── evasion/                  # 免杀规避
│   │   │   └── evasion-detail.md    # 免杀详细
│   │   ├── exchange-attack/            # Exchange攻击
│   │   │   └── exchange-detail.md   # Exchange详细
│   │   └── sharepoint-attack/         # SharePoint攻击
│   │       └── sharepoint-detail.md # SharePoint详细
│   └── tools/                         # 工具命令
│       ├── nmap.md
│       ├── sqlmap.md
│       ├── metasploit.md
│       ├── hydra.md
│       ├── john.md
│       ├── hashcat.md
│       ├── crackmapexec.md
│       ├── impacket.md
│       ├── powershell.md
│       ├── linux-privesc.md
│       ├── gobuster.md
│       ├── ffuf.md
│       └── reverse-shell.md
```

## 快速索引

### 按漏洞类型

| 漏洞类型 | 目录 | WAF绕过 | 攻击链 | 详细分类 |
|----------|------|---------|----------|----------|
| SQL注入 | `web/sqli/` | `waf-bypass.md` | `attack-chain.md` | `time-blind.md`, `error-based.md`, `blind.md` |
| XSS | `web/xss/` | `waf-bypass.md` | `attack-chain.md` | `xss-detail.md` |
| SSRF | `web/ssrf/` | `waf-bypass.md` | `attack-chain.md` | `ssrf-detail.md` |
| RCE | `web/rce/` | `waf-bypass.md` | `attack-chain.md` | `rce-detail.md` |
| LFI | `web/lfi/` | `waf-bypass.md` | `attack-chain.md` | `lfi-detail.md` |
| XXE | `web/xxe/` | `waf-bypass.md` | `attack-chain.md` | - |
| SSTI | `web/ssti/` | `waf-bypass.md` | `attack-chain.md` | `ssti-detail.md` |
| CSRF | `web/csrf.md` | - | - | - |
| 认证漏洞 | `web/auth.md` | - | - | `auth-detail.md` |
| 文件漏洞 | `web/file-vulns.md` | - | - | - |
| 缓存与CDN | `web/cache-cdn.md` | - | - | `cache-cdn-detail.md` |
| HTTP请求走私 | `web/smuggling.md` | - | - | - |
| 开放重定向 | `web/redirect.md` | - | - | - |
| 点击劫持 | `web/clickjacking.md` | - | - | `clickjacking-detail.md` |
| 业务逻辑 | `web/biz-logic.md` | - | - | `biz-logic-detail.md` |
| JWT安全 | `web/jwt.md` | - | - | `jwt-detail.md` |
| 供应链攻击 | `web/supply-chain.md` | - | - | - |
| 原型链污染 | `web/prototype-pollution.md` | - | - | - |
| 云安全 | `web/cloud.md` | - | - | `cloud-detail.md` |
| WebSocket安全 | `web/websocket.md` | - | - | - |
| AI安全 | `web/ai-security.md` | - | - | - |
| API安全 | `web/api.md` | - | - | `api-detail.md` |
| 框架漏洞 | `web/framework.md` | - | - | `framework-detail.md` |

### 按内网渗透阶段

| 阶段 | 目录 | 详细分类 |
|------|------|----------|
| 信息收集 | `intranet/recon/` | `intranet-detail.md` |
| 凭证窃取 | `intranet/cred theft/` | `credential-theft-detail.md` |
| 横向移动 | `intranet/lateral/` | `lateral-detail.md` |
| 权限提升 | `intranet/privesc/` | `privesc-detail.md` |
| 权限维持 | `intranet/persistence/` | - |
| 隧道代理 | `intranet/tunnel/` | `tunnel-detail.md` |
| 域渗透 | `intranet/ad-attack/` | `ad-attack-detail.md` |
| 免杀规避 | `intranet/evasion/` | `evasion-detail.md` |
| Exchange攻击 | `intranet/exchange-attack/` | `exchange-detail.md` |
| SharePoint攻击 | `intranet/sharepoint-attack/` | `sharepoint-detail.md` |

---

*数据来源于 Payloader 项目*
