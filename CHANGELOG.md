# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-01

### Added

#### Module 1: 工具迁移
- 新增12个安全工具完整实现（nmap, nuclei, sqlmap, ffuf, gobuster, whatweb, crackmapexec, impacket, bloodhound, hydra, dirsearch, fscan）
- 工具Schema定义和Handler实现
- SSRF防护机制
- 命令注入防护
- 私有IP限制（内网工具专用）

#### Module 2: Skill系统
- 新增8个技能包（web_exploitation, internal_network, api_security_testing, pwn_exploitation, crypto_exploitation, reverse_engineering, ai_security, misc_challenges）
- 整合skill-play-main专业渗透测试知识库（85+文档）
- 知识库引用机制

#### Module 3: 缺失模块补全
- 报告生成器（Markdown/HTML/JSON格式）
- 结果可视化引擎（Mermaid攻击树、网络拓扑）
- 配置管理系统（YAML配置）

#### Module 4: Claude Code架构改进
- 上下文压缩引擎（Prompt Cache，90% Token节省）
- 错误恢复机制（指数退避重试）
- 增量记忆系统（知识强度衰减）
- 错误知识库积累

#### Module 5: 前端界面
- React 18 + TypeScript框架
- Tailwind CSS深色主题
- Zustand状态管理
- AgentStatusCard核心组件
- Dashboard基础布局

### Security

- 移除硬编码API密钥
- 添加config.yaml.example模板
- .gitignore排除敏感配置

### Fixed

- 修复Memory系统命名冲突
- Dockerfile添加whatweb和gobuster安装
- 工具注册完整性验证

## [1.0.0] - 2025-12-01

### Added

- 基础Agent架构
- LangGraph状态机
- 工具调用框架
- Web UI监控界面
- Docker部署支持
- 7个基础工具

---

## 版本说明

- **[2.0.0]** - 完整重构版本，借鉴Claude Code架构
- **[1.0.0]** - 初始发布版本
