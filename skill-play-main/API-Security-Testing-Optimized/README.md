# API Security Testing Skill

[![Version](https://img.shields.io/badge/version-4.0-blue)](https://github.com/steveopen1/skill-play)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Agent 驱动的 API 安全测试 Skill**，通过 YAML frontmatter 定义触发条件，自动调用 `core/` 模块执行安全测试。

---

## 核心设计理念

| 理念 | 说明 |
|------|------|
| **Skill 是框架，不是脚本** | SKILL.md 定义决策流程，core/ 提供执行能力 |
| **语义分析优先** | 路径模式只是线索，需要分析接口语义决定下一步 |
| **模块化能力池** | core/ 是能力池，根据目标特征动态组合 |
| **多维度判断** | 不依赖单一指标，综合评估漏洞风险 |

---

## 核心能力

### 多维度漏洞检测

| 维度 | 检测项 | 说明 |
|------|--------|------|
| D1 | 状态码 | 200/401/403/404/500 |
| D2 | 响应内容 | 敏感字段、业务数据、错误信息 |
| D3 | 认证绕过 | Token/Cookie/Session 验证 |
| D4 | 敏感暴露 | 密码/密钥/个人数据/配置 |
| D5 | 未授权操作 | 增/删/改/查 权限 |
| D6 | 业务上下文 | 端点功能分类 |

### 专项检测能力

| 类型 | 触发条件 | 检测内容 |
|------|---------|---------|
| **云存储** | 响应包含 `<ListBucket>` 等 | OSS/COS/S3/MinIO 漏洞 |
| **GraphQL** | `/graphql` 或 `__schema` | 嵌套遍历/权限绕过 |
| **IDOR** | 资源 ID 参数 | 越权访问 |
| **暴力破解** | 登录接口 | 验证码/rate limit |
| **WebSocket** | `Upgrade: websocket` | 协议安全 |

---

## 目录结构

```
api-security-testing/
├── SKILL.md                      # Skill 入口 (YAML frontmatter)
├── README.md                     # 本文件
├── requirements.txt              # Python 依赖
├── core/                         # 核心能力模块
│   ├── orchestrator.py           # 智能编排器
│   ├── browser_tester.py         # 浏览器测试 (SPA/JS分析)
│   ├── deep_api_tester_v55.py   # API 深度测试
│   ├── api_fuzzer.py            # 模糊测试
│   ├── cloud_storage_tester.py   # 云存储安全测试
│   ├── advanced_recon.py         # 高级侦察
│   ├── reasoning_engine.py        # 推理引擎
│   └── context_manager.py        # 上下文管理
├── references/                   # Agent 决策参考文档
│   ├── graphql-guidance.md      # GraphQL 测试指导
│   ├── rest-guidance.md         # REST API 测试指导
│   ├── asset-discovery.md        # 资产发现方法
│   ├── test-matrix.md           # 测试矩阵
│   ├── validation.md           # 验证标准
│   ├── severity-model.md       # 严重性分级
│   └── report-template.md     # 报告模板
├── templates/                    # 报告模板
└── examples/                     # 使用示例
```

---

## 快速开始

### 作为 Skill 使用

```bash
# 完整扫描
请对这个 API 进行全面的安全测试

# 检查云存储
帮我检测 OSS 存储桶安全

# GraphQL 测试
检查 GraphQL 有什么漏洞

# 生成报告
生成一份完整的安全测试报告
```

### 作为 Python 模块使用

```python
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

from core.deep_api_tester_v55 import DeepAPITesterV55
from core.cloud_storage_tester import CloudStorageTester

# API 深度测试
api_tester = DeepAPITesterV55(target='http://target.com', headless=True)
api_tester.run_test()

# 云存储测试
storage_tester = CloudStorageTester()
results = storage_tester.full_test('http://bucket.oss-region.aliyuncs.com')
```

---

## 执行流程

```
触发条件 (YAML frontmatter)
    ↓
阶段 0: 前置检查
    ├── 安装依赖
    ├── 验证 core 模块
    └── 能力检查
    ↓
阶段 1: 资产发现
    ├── 目标探测
    ├── SPA/JS 分析
    └── 端点发现
    ↓
阶段 2: 多维度分析
    ├── GraphQL 检测? → 语义分析
    ├── 云存储检测? → 响应确认
    ├── IDOR 检测? → 权限分析
    ├── 暴力破解? → 防护测试
    └── WebSocket? → 协议分析
    ↓
阶段 3: 漏洞验证
    └── 多维度综合评分
    ↓
阶段 4: 报告生成
```

---

## 云存储检测 (Phase 5)

支持厂商: 阿里云 OSS | 腾讯云 COS | 华为云 OBS | AWS S3 | MinIO

### 检测能力

| 漏洞类型 | 风险等级 | 检测方法 |
|---------|---------|---------|
| 公开可列目录 | Critical | GET / → XML 文件列表 |
| 匿名 PUT 上传 | Critical | PUT /test.txt |
| 敏感文件泄露 | Critical | .env, .sql, .bak |
| 目录遍历 | High | ../../etc/passwd |
| CORS 配置过宽 | High | Access-Control-Allow-Origin |
| 日志泄露 | Medium | /logs/, /accesslog/ |
| 目录递减探测 | Medium | 递归探索子目录 |
| 常见路径探测 | Medium | /backup/, /config/ |

### 智能识别

```python
# URL 域名模式
*.oss-aliyuncs.com  → 阿里云
*.cos.myqcloud.com   → 腾讯云
*.s3.amazonaws.com   → AWS S3

# 响应头特征
X-OSS-*              → 阿里云
X-Amz-*              → AWS
X-Minio-*            → MinIO

# 响应内容特征
<ListBucketResult>    → 存储桶
<AccessControlPolicy> → ACL 配置
```

---

## 漏洞判定算法

```python
RiskScore = (
    D1_StateCode * 0.15 +
    D2_Content * 0.20 +
    D3_AuthBypass * 0.25 +
    D4_SensitiveExposure * 0.20 +
    D5_UnauthorizedAction * 0.15 +
    D6_BusinessContext * 0.05
)

# 风险等级
- Critical: Score >= 80
- High: Score >= 60
- Medium: Score >= 40
- Low: Score >= 20
- Info: Score < 20
```

---

## 报告输出

```markdown
## Scope
- Target: [目标 URL]
- Assessment Mode: [被动/主动]

## Asset Summary
- API Type: [REST/GraphQL/SPA+API]
- Tech Stack: [技术栈]
- Endpoints: [端点数量]

## Findings

### Finding N: [漏洞标题]
**Severity**: Critical
**Confidence**: Confirmed
**Multi-Dimension Analysis**:
| 维度 | 得分 | 分析 |
|------|------|------|
| D1 状态码 | 15/15 | [分析] |
| D2 响应内容 | 18/20 | [分析] |
| D3 认证绕过 | 25/25 | [分析] |
...
```

---

## 道德声明

本 Skill **仅限授权测试使用**。

- ✅ 用于自己拥有的系统
- ✅ 用于获得书面授权的系统
- ✅ 用于安全研究和教育目的

---

*最后更新：2026-04-01*
