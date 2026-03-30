# CTF Agent：基于LangGraph的自主渗透测试智能体

> 团队原创，转载请注明出处

---

## 项目背景

随着网络安全攻防演练和CTF竞赛的普及，自动化渗透测试工具的需求日益增长。传统工具往往依赖人工操作，难以应对复杂的多层网络环境。我们团队基于大语言模型和图编排技术，开发了CTF Agent——一个能够自主完成渗透测试任务的智能体系统。

---

## 核心架构

CTF Agent采用**LangGraph**作为核心编排框架，将渗透测试流程抽象为可组合的有向图结构，实现了灵活的任务调度和状态管理。

### 架构亮点

- **图节点化设计**：将侦察、分析、攻击、验证等环节抽象为独立节点，支持动态路由
- **状态持久化**：完整的任务状态管理，支持断点续传和错误恢复
- **模块化工具链**：集成52个安全工具，按需动态加载
- **RAG知识增强**：结合向量数据库检索13,000+条历史Writeup和Payload，提升攻击成功率

---

## 功能特性

### 1. 八大CTF方向全覆盖

| 方向 | 核心能力 | 关键节点 |
|------|----------|----------|
| Web安全 | SQL注入、XSS、SSTI、SSRF、文件上传 | recon → analyst → attacker → verifier |
| 内网渗透 | 后渗透、横向移动、权限提升、凭据窃取 | post_exploit → lateral_move → privilege_escalation |
| 密码学 | 古典密码、现代加密、哈希破解 | crypto_analyst → crypto_solver |
| Pwn | 栈溢出、堆利用、ROP链构造 | pwn_analyst → pwn_exploiter |
| 逆向 | 反编译、算法还原、密钥提取 | reverse_analyst → reverse_decompiler |
| Misc | 隐写术、取证分析、编码解码 | misc_analyst → misc_extractor |
| AI安全 | Prompt注入、模型越狱、数据泄露 | ai_detect → ai_probe → ai_exploit |
| 云安全 | 云元数据泄露、容器逃逸、IAM攻击 | cloud_recon → cloud_enum → cloud_exploit |

### 2. AI驱动全流程决策

系统所有决策节点均由AI驱动，避免硬编码规则：

- **侦察节点**：自动识别技术栈、发现隐藏路径、分析WAF特征
- **分析节点**：漏洞优先级排序、攻击链规划、知识库检索
- **攻击节点**：动态Payload生成、多工具协同、自动绕过
- **验证节点**：Flag格式校验、攻击结果确认、进度评估

![Web监控界面](./images/web_monitor.png)
*Web任务监控界面 - 实时展示节点执行状态*

### 3. 智能模块管理

系统根据当前任务场景动态加载所需模块，实现内存资源优化：

- **Web模式**：加载SQLMap、Nuclei、Dalfox等Web工具
- **内网模式**：加载Mimikatz、BloodHound、CrackMapExec等内网工具
- **模式切换响应时间 < 2秒**

![模块管理界面](./images/module_manager.png)
*模块管理界面 - 实时启用/禁用功能模块*

### 4. 性能监控面板

内置性能监控系统，实时追踪：

- 节点执行耗时统计
- LLM调用Token消耗
- 工具执行成功率
- 缓存命中率

![性能监控界面](./images/performance.png)
*性能监控面板 - 节点/LLM/工具耗时分析*

### 5. 站点拓扑分析

自动构建目标站点结构图，支持：

- 页面关系可视化
- 差异检测（对比页面变化）
- 智能剪枝（过滤无关页面）

![拓扑分析界面](./images/topology.png)
*站点拓扑图 - 页面结构与攻击面可视化*

---

## 技术实现

### 工具集成

项目集成52个模块化安全工具，覆盖渗透测试全流程：

| 分类 | 工具列表 |
|------|---------|
| 漏洞扫描 | Nuclei、Xray、Fscan、Nmap |
| 注入攻击 | SQLMap、Fenjing(SSTI)、Dalfox(XSS)、XXEInjector |
| 反序列化 | Ysoserial、PHPGGC、Marshalsec、Pickle-Pwn |
| 内网渗透 | Impacket、CrackMapExec、Mimikatz、Metasploit |
| 域渗透 | BloodHound、PetitPotam、Rubeus、Kerberos攻击 |
| SSRF利用 | SSRFMap、Gopherus |
| 云安全 | CloudScanner、Kube-Attacker |
| AI攻击 | AI-Attacker |

### RAG知识检索系统

基于ChromaDB构建的向量知识库：

| 知识源 | 记录数 | 用途 |
|--------|--------|------|
| CTF Writeups | 122篇 | 历史解题思路参考 |
| Nuclei模板 | 12,763条 | 漏洞检测规则库 |
| Payload集合 | 103个 | 攻击载荷知识库 |
| 安全资源 | 61份 | 技术文档与字典 |

```
向量数据库总记录: 13,049条
存储大小: ~70MB
检索延迟: <100ms
```

### 提示词工程

针对渗透测试场景，设计了三层提示词体系：

1. **分析层**：场景联想、漏洞优先级排序、知识库检索增强
2. **执行层**：攻击决策推理、工具选择、预期结果预判
3. **验证层**：进度评估、策略调整建议、失败权重计算

---

## 部署方式

### Docker一键部署（推荐）

```bash
# 克隆项目
git clone https://github.com/yinyu-cybersecurity/ctf_agent.git
cd ctf_agent

# 配置API Key
cp config.yaml.example config.yaml
# 编辑 config.yaml，填入 LLM API Key

# 启动服务
docker-compose up -d --build

# 查看日志
docker logs -f ctf-agent
```

访问 `http://localhost:54565/fisher_ctf_agent/monitor` 即可使用Web控制台。

### 本地运行

```bash
pip install -r requirements.txt
python web/api.py
# 访问: http://localhost:54565/fisher_ctf_agent/monitor
```

![任务创建界面](./images/task_create.png)
*任务创建界面 - 输入目标URL开始自动化渗透*

---

## 项目统计

| 项目 | 数量 |
|------|------|
| 安全工具 | 52 |
| 第三方工具 | 22 |
| CTF方向模块 | 8 |
| 状态类型 | 8 |
| RAG向量记录 | 13,049 |
| 核心代码行数 | ~50,000 |

---

## 开源地址

项目已开源，欢迎社区贡献：

**GitHub**: https://github.com/yinyu-cybersecurity/ctf_agent

---

## 未来规划

- [ ] 支持更多云平台（AWS、Azure、GCP）
- [ ] 增强反序列化漏洞检测能力
- [ ] 优化多任务并发调度
- [ ] 完善自动化报告生成
- [ ] 支持多语言国际化

---

## 安全提醒

⚠️ **本项目仅供授权安全测试和CTF竞赛使用**

- 请确保在合法授权环境下使用
- 不要将真实API Key上传到代码库
- 攻击结果可能包含敏感信息，请妥善保管

---

## 团队介绍

我们是一支专注于网络安全攻防技术研究的团队，在CTF竞赛和红蓝对抗领域积累了丰富经验。CTF Agent是团队在智能化安全工具方向的探索成果，期待与社区共同完善。

---

**关注我们，获取更多安全技术分享**

![公众号二维码](./images/qrcode.png)
*扫码关注公众号*

---

*本文首发于微信公众号，作者：安全研究团队*