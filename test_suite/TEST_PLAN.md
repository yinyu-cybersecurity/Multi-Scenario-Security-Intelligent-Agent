# CTF-Agent 测试题集方案

## 测试目标
验证框架在四个赛区的自动化渗透能力，通过日志分析发现问题并迭代修复。

---

## 第一赛区：识器·明理（Web安全基础）

**目标**: 验证自动化漏洞扫描与利用能力

### NSSCTF 题目推荐

| 题目名称 | 漏洞类型 | 验证能力 | 难度 |
|---------|---------|---------|-----|
| [NISACTF 2022] easysql | SQL注入 | sqlmap自动化注入 | ⭐ |
| [SWPUCTF 2021 新生赛] sql | SQL注入 | 联合注入 | ⭐ |
| [NSSRound#1 Basic] basic_sql | SQL注入 | 报错注入 | ⭐⭐ |
| [HNCTF 2022 WEEK2] Easy_Sql | SQL注入 | 二次注入 | ⭐⭐ |
| [NCTF 2019] True XML Cookbook | XXE | XXE漏洞利用 | ⭐⭐ |
| [SWPUCTF 2021 新生赛] pop | 反序列化 | PHP反序列化 | ⭐⭐ |
| [NISACTF 2022] Reverse | 反序列化 | PHP反序列化POP链 | ⭐⭐⭐ |
| [NSSRound#3 Basic] checkin | 文件上传 | 文件上传绕过 | ⭐⭐ |
| [HNCTF 2022 WEEK2] Include | 文件包含 | PHP伪协议 | ⭐ |
| [NCTF 2022] ReTake1 | SSRF | SSRF利用 | ⭐⭐⭐ |
| [极客大挑战 2019] EasySQL | SQL注入 | 万能密码 | ⭐ |
| [极客大挑战 2019] Havefun | 代码审计 | 简单逻辑漏洞 | ⭐ |
| [强网杯 2019] 随便注 | SQL注入 | 堆叠注入 | ⭐⭐⭐ |
| [SUCTF 2019] EasyWeb | 多漏洞 | 综合利用 | ⭐⭐⭐⭐ |
| [De1CTF 2019] SSRF Me | SSRF | SSRF+Redis | ⭐⭐⭐⭐ |

### 验证点
- [ ] recon_node 能否识别技术栈
- [ ] analyst_node 能否准确定位漏洞类型
- [ ] attacker_node 能否成功利用漏洞
- [ ] verifier_node 能否验证漏洞有效性

---

## 第二赛区：洞见·虚实（CVE复现）

**目标**: 验证CVE漏洞自动识别与利用能力

### 春秋云境 CVE 靶场

| 靶场名称 | CVE编号 | 漏洞类型 | 验证能力 |
|---------|---------|---------|---------|
| Log4j2 RCE | CVE-2021-44228 | JNDI注入 | nuclei扫描+JNDI利用 |
| Spring4Shell | CVE-2022-22965 | RCE | nuclei扫描+Tomcat写入 |
| Spring Cloud Gateway | CVE-2022-22947 | SpEL注入 | nuclei扫描 |
| Apache Shiro | CVE-2016-4437 | 反序列化 | shiro检测+ysoserial |
| WebLogic RCE | CVE-2020-14882 | 未授权RCE | nuclei+payload |
| Apache Tomcat AJP | CVE-2020-1938 | 文件读取 | ajp-shooter |
| Fastjson RCE | CVE-2022-25845 | 反序列化 | JNDI利用 |
| ThinkPHP 5.x RCE | CVE-2018-20062 | RCE | 框架漏洞利用 |
| Apache Solr RCE | CVE-2019-17558 | Velocity注入 | nuclei扫描 |
| Confluence RCE | CVE-2023-22515 | 权限绕过 | nuclei扫描 |
| Jenkins CLI | CVE-2024-23897 | 任意文件读取 | nuclei扫描 |
| Redis未授权 | 无CVE | 未授权访问 | redis写shell |

### NSSCTF CVE 相关

| 题目名称 | CVE/漏洞 | 难度 |
|---------|---------|-----|
| [QBSCTF 2021] Log4j | Log4Shell | ⭐⭐ |
| [NCTF 2022] CVE_reappear | CVE复现 | ⭐⭐⭐ |
| [SWPUCTF 2022 新生赛] ez_ez_unserialize | 反序列化 | ⭐⭐ |

### 验证点
- [ ] nuclei扫描能否识别CVE
- [ ] CVE模板是否完整
- [ ] 漏洞利用链是否完整
- [ ] exp生成是否正确

---

## 第三赛区：执刃·循迹（多层网络/OA）

**目标**: 验证内网渗透与OA漏洞利用能力

### 春秋云境 OA靶场

| 靶场名称 | 系统类型 | 攻击链 | 难度 |
|---------|---------|-------|-----|
| 致远OA综合利用 | Seeyon OA | 文件上传+RCE | ⭐⭐⭐ |
| 泛微OA漏洞利用 | Weaver e-cology | SQL注入+文件上传 | ⭐⭐⭐ |
| 通达OA综合利用 | Tongda OA | 任意文件上传+RCE | ⭐⭐⭐ |
| 用友NC综合利用 | Yonyou NC | 反序列化+RCE | ⭐⭐⭐⭐ |
| 蓝凌OA漏洞 | Landray OA | SSRF+信息泄露 | ⭐⭐⭐ |
| 禅道CMS漏洞 | Zentao | SQL注入+RCE | ⭐⭐ |

### NSSCTF 多层网络

| 题目名称 | 场景 | 验证能力 |
|---------|-----|---------|
| [第五空间 2021] EasyWeb | Web入口 | 综合利用 |
| [RoarCTF 2019] EasyJava | Java安全 | 反序列化 |
| [网鼎杯 2020 青龙组] AreUSerialz | 反序列化 | PHP反序列化 |

### 验证点
- [ ] OA系统指纹识别
- [ ] OA漏洞库覆盖度
- [ ] 多步攻击规划
- [ ] 权限维持能力

---

## 第四赛区：铸剑·止戈（域渗透）

**目标**: 验证Active Directory渗透能力

### 春秋云境 域渗透靶场

| 靶场名称 | 场景 | 攻击链 |
|---------|-----|-------|
| 红日安全-ATT&CK | 域环境 | 信息收集→横向移动→域控 |
| VulnStack系列 | 多层网络 | Web入口→内网→域控 |
| 企业内网渗透 | 完整域环境 | 凭据收集→PTH→DCSync |
| 红队评估系列 | 综合环境 | 多协议利用→域渗透 |

### 攻击路径验证

1. **信息收集**: fscan扫描、BloodHound分析
2. **凭据获取**: mimikatz、procdump
3. **横向移动**: impacket、crackmapexec
4. **权限提升**: PrintSpoofer、SweetPotato
5. **域控攻击**: DCSync、Golden Ticket

### 验证点
- [ ] 内网扫描能力（fscan/nmap）
- [ ] 凭据提取能力（mimikatz）
- [ ] 横向移动能力（impacket）
- [ ] 权限提升能力（potato系列）
- [ ] 域攻击能力（DCSync等）

---

## 测试流程

### Phase 1: 单功能测试（第一赛区）
```bash
# 逐题测试，验证每个工具链
python ctf_agent_graph.py --target <题目URL>
```

### Phase 2: CVE能力测试（第二赛区）
```bash
# 测试nuclei扫描和CVE利用
python ctf_agent_graph.py --target <靶场URL>
```

### Phase 3: 复杂场景测试（第三赛区）
```bash
# 测试OA漏洞和多层网络
python ctf_agent_graph.py --target <OA靶场URL>
```

### Phase 4: 域渗透测试（第四赛区）
```bash
# 需要先获取WebShell，再启动内网渗透
python ctf_agent_graph.py --target <内网IP段> --mode internal
```

---

## 日志分析重点

### 成功指标
- `vulnerable: true` - 发现漏洞
- `vuln_confirmed: true` - 漏洞确认
- `shell_obtained: true` - 获取Shell
- `flag_found: true` - 找到Flag

### 失败诊断
- 工具执行失败 → 检查工具安装
- LLM分析错误 → 检查prompt设计
- 路由死循环 → 检查router逻辑
- 超时终止 → 检查timeout配置

---

## 快速开始

```bash
# 进入Docker容器
docker exec -it ctf-agent bash

# 运行测试
cd /app
python ctf_agent_graph.py

# 输入题目URL开始测试
```