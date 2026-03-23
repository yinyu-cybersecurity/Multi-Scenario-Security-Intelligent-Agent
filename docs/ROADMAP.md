# CTF-Agent 项目路线图

## 项目愿景
构建基于 LangGraph 的自动化 CTF 攻击 Agent，支持 Web CTF 和内网渗透测试。

---

## 里程碑规划

### 🎯 Milestone 1: 核心框架搭建 (Week 1-2)
**目标**: 完成基础架构和核心节点

| 任务 | 负责人 | 状态 | 截止日期 |
|------|--------|------|----------|
| 项目初始化 & 仓库配置 | - | ⬜ TODO | - |
| State 状态管理设计 | - | ⬜ TODO | - |
| Router 路由逻辑实现 | - | ⬜ TODO | - |
| LLM Client 封装 | - | ⬜ TODO | - |
| 基础 Tool Framework | - | ⬜ TODO | - |

**验收标准**:
- [ ] 能够运行基本的状态流转
- [ ] LLM 调用正常返回
- [ ] 单元测试覆盖率 > 60%

---

### 🎯 Milestone 2: Web CTF 能力 (Week 3-4)
**目标**: 实现 Web 攻击自动化

| 任务 | 负责人 | 状态 | 截止日期 |
|------|--------|------|----------|
| recon_node 侦察节点 | - | ⬜ TODO | - |
| analyst_node 分析节点 | - | ⬜ TODO | - |
| attacker_node 攻击节点 | - | ⬜ TODO | - |
| verifier_node 验证节点 | - | ⬜ TODO | - |
| SQL注入工具集成 | - | ⬜ TODO | - |
| XSS/SSRF 工具集成 | - | ⬜ TODO | - |

**验收标准**:
- [ ] 能自动识别并利用 SQL 注入漏洞
- [ ] 能完成 DVWA 靶场基础关卡

---

### 🎯 Milestone 3: 内网渗透能力 (Week 5-6)
**目标**: 实现内网扫描和横向移动

| 任务 | 负责人 | 状态 | 截止日期 |
|------|--------|------|----------|
| internal_recon_node | - | ⬜ TODO | - |
| lateral_move_node | - | ⬜ TODO | - |
| Nmap 工具集成 | - | ⬜ TODO | - |
| Impacket 工具集成 | - | ⬜ TODO | - |
| 凭证管理模块 | - | ⬜ TODO | - |

**验收标准**:
- [ ] 能完成内网主机发现
- [ ] 能利用已获取凭证横向移动

---

### 🎯 Milestone 4: 智能化增强 (Week 7-8)
**目标**: 自我纠错和学习能力

| 任务 | 负责人 | 状态 | 截止日期 |
|------|--------|------|----------|
| innovator_node 创新节点 | - | ⬜ TODO | - |
| evolution_node 进化节点 | - | ⬜ TODO | - |
| self_correction 自纠错模块 | - | ⬜ TODO | - |
| RAG 知识库集成 | - | ⬜ TODO | - |
| Memory 持久化 | - | ⬜ TODO | - |

**验收标准**:
- [ ] 失败后能自动调整策略
- [ ] 能从历史攻击中学习

---

### 🎯 Milestone 5: 生产化部署 (Week 9-10)
**目标**: Docker 部署和文档完善

| 任务 | 负责人 | 状态 | 截止日期 |
|------|--------|------|----------|
| Docker 镜像优化 | - | ⬜ TODO | - |
| 配置管理优化 | - | ⬜ TODO | - |
| API 接口开发 | - | ⬜ TODO | - |
| 文档完善 | - | ⬜ TODO | - |
| 压力测试 | - | ⬜ TODO | - |

**验收标准**:
- [ ] 一键 Docker 部署
- [ ] 完整的用户文档

---

## 技术栈

| 类别 | 技术选型 |
|------|----------|
| 框架 | LangGraph, LangChain |
| LLM | DeepSeek / OpenAI / Claude |
| 工具 | Nmap, SQLMap, Nuclei, Impacket |
| 部署 | Docker, Docker Compose |
| 存储 | Redis, ChromaDB |

---

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| LLM API 不稳定 | 高 | 多模型切换, 重试机制 |
| 工具执行失败 | 中 | Self-correction 模块 |
| 内网环境限制 | 中 | Docker 网络隔离测试 |

---

## 更新日志

| 日期 | 更新内容 |
|------|----------|
| 2026-03-23 | 初始化路线图 |