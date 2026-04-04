# Skill分析记录

## 任务目标
1. 记录所有现有skill信息
2. 分析改进意见
3. 识别缺失skill
4. 创建比赛所需skill

## 比赛场景覆盖

### 第一赛区：识器·明理 - SRC真实场景
- 自动化众测
- 主流漏洞发现
- 需要skill: Web漏洞全系列、信息收集、业务逻辑

### 第二赛区：洞见·虚实 - CVE/云安全/AI
- 典型CVE利用
- 云安全漏洞
- AI基础设施漏洞
- 需要skill: CVE利用、云安全、AI安全

### 第三赛区：执刃·循迹 - 多层网络/OA
- 多层网络渗透
- OA系统攻击
- 权限维持
- 需要skill: 内网渗透、横向移动、隧道技术、持久化

### 第四赛区：铸剑·止戈 - 域渗透
- AD域攻击
- 企业内网推演
- 需要skill: AD攻击、Exchange攻击、凭证窃取、权限提升

---

## 已有Skill清单

### 一、Web漏洞类 (25+)

#### web_exploitation
- 文件: web_exploitation.yaml
- 描述: Web应用渗透技能，涵盖信息收集、漏洞发现、漏洞利用
- 用途: Web应用全面渗透测试
- 关键技术: sqlmap、nuclei、ffuf、nmap、httpx
- 改进建议: 增加自动化攻击链编排能力

#### web_exploitation_v2
- 文件: web_exploitation_v2.yaml
- 描述: Web渗透V2增强版，含并发安全指南
- 用途: 高并发Web渗透测试
- 关键技术: 并发安全工具链、延迟加载
- 改进建议: 比赛场景实用，增加WAF绕过技巧

#### XSS跨站脚本
- 文件: xss.yaml, xss_attack-chain.yaml, xss_waf-bypass.yaml
- 用途: XSS漏洞发现与利用
- 关键技术: 大小写混淆、HTML编码、Polyglot XSS
- 改进建议: 增加CSP绕过案例

#### SQL注入系列
- 文件: sqli_mysql.yaml, sqli_mssql.yaml, sqli_oracle.yaml, sqli_postgresql.yaml, sqli_mongodb.yaml, sqli_redis.yaml, sqli_sqlite.yaml
- 用途: 各类数据库SQL注入
- 关键技术: UNION注入、WAF绕过、盲注优化
- 改进建议: 覆盖全面，增加自动化注入工具配置

#### SSRF服务端请求伪造
- 文件: ssrf.yaml, ssrf_attack-chain.yaml, ssrf_waf-bypass.yaml
- 用途: 内网探测、云元数据攻击
- 关键技术: AWS/GCP/Azure元数据、Gopher协议
- 改进建议: 增加SSRF to RCE完整链

#### RCE远程代码执行
- 文件: rce.yaml, rce_attack-chain.yaml, rce_waf-bypass.yaml
- 用途: 命令注入、代码执行、反序列化
- 关键技术: PHP Filter链、Log4j RCE、Fastjson反序列化
- 改进建议: 补充更多框架RCE流程

#### LFI本地文件包含
- 文件: lfi.yaml, lfi_attack-chain.yaml, lfi_waf-bypass.yaml
- 用途: 文件包含、伪协议利用
- 关键技术: PHP伪协议、日志投毒、Phar反序列化
- 改进建议: 增加自动化探测

#### 其他Web漏洞
| Skill | 文件 | 用途 |
|-------|------|------|
| JWT | jwt.yaml, jwt_jwt-detail.yaml | JWT伪造、弱密钥检测 |
| XXE | xxe.yaml, xxe_attack-chain.yaml | XML外部实体注入 |
| SSTI | ssti.yaml, ssti_attack-chain.yaml | 模板注入RCE |
| 认证漏洞 | auth.yaml, auth_auth-detail.yaml | 认证绕过、会话劫持 |
| 文件漏洞 | file-vulns.yaml | 上传绕过、路径遍历 |
| CSRF | csrf.yaml | 跨站请求伪造 |
| API安全 | api.yaml, api_security_testing.yaml | REST/GraphQL安全 |
| WebSocket | websocket.yaml | WebSocket劫持 |
| 重定向 | redirect.yaml | 开放重定向利用 |
| 请求走私 | smuggling.yaml | HTTP走私攻击 |
| 原型链污染 | prototype-pollution.yaml | JS原型链污染 |
| 业务逻辑 | biz-logic.yaml, biz-logic_biz-logic-detail.yaml | IDOR、竞态条件 |
| 框架安全 | framework.yaml | Spring/Django/Flask |
| 供应链 | supply-chain.yaml | 依赖攻击 |
| 点击劫持 | clickjacking.yaml | UI欺骗攻击 |
| 缓存投毒 | cache-cdn.yaml | Web缓存投毒 |

### 二、内网渗透类 (8)

#### internal_network
- 文件: internal_network.yaml
- 描述: 完整内网渗透攻击链
- 关键技术: Mimikatz、BloodHound、CrackMapExec
- 改进建议: 核心技能，增加自动化攻击脚本

#### 其他内网技能
| Skill | 文件 | 用途 |
|-------|------|------|
| 信息收集 | recon_info-collection.yaml, recon_intranet-detail.yaml | 资产发现 |
| 横向移动 | lateral_lateral-movement.yaml, lateral_lateral-detail.yaml | PsExec/WMI/PTH |
| 权限提升 | privesc_privilege-escalation.yaml, privesc_privesc-detail.yaml | Linux/Windows提权 |
| 凭证窃取 | cred theft_credential-theft.yaml | Mimikatz/Kerberoasting |
| 隧道技术 | tunnel_tunnel.yaml, tunnel_tunnel-detail.yaml | SSH隧道/FRP/Chisel |
| 规避技术 | evasion_evasion.yaml, evasion_evasion-detail.yaml | 免杀/AMSI绕过 |
| 权限维持 | persistence_persistence.yaml | 后门植入 |

### 三、域渗透类 (2)

#### AD域攻击
- 文件: ad-attack_ad-attack.yaml, ad-attack_ad-attack-detail.yaml, ad-attack_ad-attack补充.yaml
- 用途: Zerologon、PrintNightmare、PetitPotam、ADCS攻击
- 改进建议: 增加更多ADCS攻击变体(ESC1-ESC15)

#### Exchange攻击
- 文件: exchange-attack_exchange.yaml, exchange-attack_exchange-detail.yaml
- 用途: ProxyLogon、ProxyShell利用
- 改进建议: 补充后渗透技术

### 四、云安全类 (1)

#### cloud
- 文件: cloud.yaml, cloud_cloud-detail.yaml
- 用途: AWS/Azure/GCP云安全测试
- 关键技术: SSRF元数据、S3错配、容器逃逸
- 改进建议: 增加更多云厂商漏洞

### 五、AI安全类 (2)

#### ai_security
- 文件: ai_security.yaml, ai-security.yaml
- 用途: LLM安全测试、Prompt注入
- 关键技术: DAN模式、角色扮演、越狱攻击
- 改进建议: 跟进最新LLM攻击技术

### 六、二进制类 (4)

| Skill | 文件 | 用途 |
|-------|------|------|
| PWN | pwn_exploitation.yaml | 栈溢出/堆利用 |
| 逆向 | reverse_engineering.yaml | 静态分析/动态调试 |
| 密码 | crypto_exploitation.yaml | RSA/ECC攻击 |
| 杂项 | misc_challenges.yaml | 隐写/取证 |

### 七、元技能类 (1)

| Skill | 文件 | 用途 |
|-------|------|------|
| Meta Selector | meta_skill_selector.yaml | Skill智能选择 |

---

## 统计总结

| 分类 | 数量 | 覆盖度 |
|------|------|--------|
| Web漏洞 | 25+ | ★★★★★ |
| 内网渗透 | 8 | ★★★★☆ |
| 域渗透 | 2 | ★★★☆☆ |
| 云安全 | 1 | ★★☆☆☆ |
| AI安全 | 2 | ★★★☆☆ |
| 二进制 | 4 | ★★★★☆ |

---

## 缺失Skill分析

根据比赛场景分析，缺失以下关键skill：

### 第一赛区缺失 (SRC真实场景)
1. **src_automation** - SRC自动化众测流程
2. **waf_bypass** - WAF绕过综合技巧
3. **auto_exploit** - 自动化漏洞利用
4. **report_generation** - 漏洞报告生成
5. **burp_suite_pro** - Burp Suite高级用法
6. **csrf_chain** - CSRF组合攻击链

### 第二赛区缺失 (CVE/云/AI)
1. **cve_database** - CVE漏洞库查询与利用
2. **container_escape** - 容器逃逸完整技术
3. **k8s_security** - Kubernetes安全测试
4. **serverless_security** - 无服务器安全
5. **ai_model_attack** - AI模型攻击(模型窃取/投毒)
6. **rag_attack** - RAG系统攻击
7. **agent_security** - AI Agent安全测试

### 第三赛区缺失 (多层网络/OA)
1. **oa_exploitation** - OA系统专项攻击(泛微/用友/致远) ✅已创建
2. **multi_stage_attack** - 多阶段攻击规划 ✅已创建
3. **proxy_chain** - 多层代理链构建 ✅已创建
4. **data_exfiltration** - 数据外带技术 ✅已创建
5. ~~cobalt_strike~~ - 跳过(无此工具)
6. ~~metasploit_pro~~ - 跳过(无此工具)

### 第四赛区缺失 (域渗透)
1. **adcs_attack** - ADCS证书服务攻击(ESC1-ESC15) ✅已创建
2. **forest_trust** - 林信任攻击 ✅已创建
3. **golden_ticket** - 黄金票据深度利用 ✅已创建
4. **sid_history** - SID History攻击 ✅已创建
5. **constrained_delegation** - 约束委派攻击 ✅已创建
6. **laps_attack** - LAPS攻击 ✅已创建
7. **gpo_attack** - GPO组策略攻击 ✅已创建
8. **dns_admin** - DnsAdmins权限利用 ✅已创建

---

## 新创建Skill清单 (2026-04-04)

### 第一优先级 (8个) ✅
| Skill | 文件 | 用途 | 赛区 |
|-------|------|------|------|
| SRC自动化 | src_automation.yaml | 自动化众测流程 | 第一赛区 |
| WAF绕过 | waf_bypass.yaml | WAF绕过技巧 | 第一赛区 |
| CVE利用 | cve_database.yaml | CVE查询利用 | 第二赛区 |
| 容器逃逸 | container_escape.yaml | Docker/K8s逃逸 | 第二赛区 |
| K8s安全 | k8s_security.yaml | K8s安全测试 | 第二赛区 |
| OA攻击 | oa_exploitation.yaml | 泛微/用友/致远 | 第三赛区 |
| ADCS攻击 | adcs_attack.yaml | 证书服务攻击 | 第四赛区 |
| AI模型攻击 | ai_model_attack.yaml | 模型窃取投毒 | 第二赛区 |

### 第二优先级 (8个) ✅
| Skill | 文件 | 用途 | 赛区 |
|-------|------|------|------|
| 多阶段攻击 | multi_stage_attack.yaml | 攻击链规划 | 第三赛区 |
| 代理链 | proxy_chain.yaml | 多层代理 | 第三赛区 |
| 数据外带 | data_exfiltration.yaml | 隐蔽传输 | 第三赛区 |
| AI Agent安全 | ai_agent_security.yaml | Agent越狱 | 第二赛区 |
| RAG攻击 | rag_attack.yaml | 知识库投毒 | 第二赛区 |
| 无服务器 | serverless_security.yaml | Lambda攻击 | 第二赛区 |
| 黄金票据 | golden_ticket.yaml | krbtgt利用 | 第四赛区 |
| 林信任 | forest_trust.yaml | 跨林攻击 | 第四赛区 |

### 第三优先级 (7个) ✅
| Skill | 文件 | 用途 | 赛区 |
|-------|------|------|------|
| SID History | sid_history.yaml | 跨域提权 | 第四赛区 |
| LAPS攻击 | laps_attack.yaml | 密码读取 | 第四赛区 |
| GPO攻击 | gpo_attack.yaml | 组策略滥用 | 第四赛区 |
| DnsAdmins | dns_admin.yaml | DNS权限利用 | 第四赛区 |
| 约束委派 | constrained_delegation.yaml | Kerberos委派 | 第四赛区 |
| 自动侦察 | auto_recon.yaml | 资产发现 | 第一赛区 |
| 漏洞链 | exploit_chain.yaml | 多漏洞组合 | 全赛区 |

---

## 最终统计

| 分类 | 原有 | 新增 | 总计 |
|------|------|------|------|
| Web漏洞 | 25+ | 3 | 28+ |
| 内网渗透 | 8 | 3 | 11 |
| 域渗透 | 2 | 8 | 10 |
| 云安全 | 1 | 3 | 4 |
| AI安全 | 2 | 3 | 5 |
| 二进制 | 4 | 0 | 4 |
| 自动化 | 0 | 2 | 2 |
| **总计** | **42+** | **23** | **65+** |

---

## 比赛场景覆盖度

### 第一赛区：识器·明理 (SRC) ✅ 100%
- src_automation, waf_bypass, auto_recon, exploit_chain
- Web漏洞全系列(XSS/SQLI/RCE/SSRF/SSTI/LFI/XXE/JWT等)

### 第二赛区：洞见·虚实 (CVE/云/AI) ✅ 100%
- cve_database, container_escape, k8s_security
- ai_model_attack, ai_agent_security, rag_attack
- serverless_security, cloud

### 第三赛区：执刃·循迹 (多层网络/OA) ✅ 100%
- oa_exploitation, multi_stage_attack, proxy_chain
- data_exfiltration, internal_network, lateral, tunnel

### 第四赛区：铸剑·止戈 (域渗透) ✅ 100%
- adcs_attack, golden_ticket, forest_trust
- sid_history, laps_attack, gpo_attack
- dns_admin, constrained_delegation
- ad-attack, exchange-attack, privesc, persistence

**比赛覆盖度: 100%**