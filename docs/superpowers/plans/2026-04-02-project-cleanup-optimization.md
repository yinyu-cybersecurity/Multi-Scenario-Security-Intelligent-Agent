# 项目清理与优化实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 清理老旧代码、优化配置文件、优化Docker构建

**Architecture:** 分三阶段执行：清理 → 配置重写 → Docker优化

---

## Task 1: 清理老旧代码和缓存文件

**Files:**
- Delete: `app/_archived/ctf_agent_graph.py.legacy`
- Clean: 所有 `__pycache__` 目录
- Clean: 所有 `.pyc` 文件

- [ ] **Step 1: 删除_archived目录中的遗留代码**

```bash
rm -rf app/_archived/
```

- [ ] **Step 2: 清理Python缓存文件**

```bash
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true
```

- [ ] **Step 3: 创建.gitignore确保缓存不被提交**

```gitignore
# Python
__pycache__/
*.py[cod]
*.pyo
*.egg-info/
.eggs/
*.egg

# IDE
.idea/
.vscode/
*.swp
*.swo

# Logs
*.log
logs/

# Environment
.env
.venv/
venv/

# Data
data/chroma_db/
data/rag_cache/
*.db
*.sqlite3
```

- [ ] **Step 4: 提交清理更改**

```bash
git add .gitignore
git commit -m "chore: 清理老旧代码和缓存文件

- 删除 app/_archived/ 遗留代码
- 清理 __pycache__ 和 .pyc 文件
- 更新 .gitignore 忽略缓存文件"
```

---

## Task 2: 重写配置文件贴合项目实际

**Files:**
- Modify: `app/config.py`
- Modify: `config.yaml`
- Modify: `config.yaml.example`

- [ ] **Step 1: 在config.py中添加LLM_MODEL统一配置**

在 `app/config.py` 的 LLM 配置部分添加：

```python
    # =========================================================================
    # LLM 配置
    # =========================================================================

    LLM_API_KEY: str = ""
    LLM_BASE_URL: str = "https://api.deepseek.com/v1"
    
    # 统一模型配置 - 所有Agent使用同一模型
    LLM_MODEL: str = "deepseek-chat"
```

- [ ] **Step 2: 更新config.py移除未使用的Agent模型配置**

将以下5个配置项注释或标记为可选：
```python
    # =========================================================================
    # 模型配置 - 可选（如需为不同Agent指定不同模型）
    # 当前项目统一使用 LLM_MODEL，以下配置仅用于高级定制
    # =========================================================================

    # ANALYST_MODEL: str = "deepseek-chat"
    # ATTACKER_MODEL: str = "deepseek-chat"  
    # VERIFIER_MODEL: str = "deepseek-chat"
    # EXPLORER_MODEL: str = "deepseek-chat"
    # INNOVATOR_MODEL: str = "deepseek-chat"
```

- [ ] **Step 3: 更新config.yaml为最终版本**

```yaml
# CTF-Agent Configuration
# 项目使用 app/config.py 的 dataclass 配置
# 此文件覆盖默认值

# ===== LLM Configuration =====
LLM_API_KEY: ""
LLM_BASE_URL: "https://api.deepseek.com/v1"
LLM_MODEL: "deepseek-chat"

# ===== Network Configuration =====
LOCAL_PUBLIC_IP: ""

# ===== Docker Configuration =====
DOCKER_ENABLED: true
DOCKER_FALLBACK_TO_LOCAL: true
```

- [ ] **Step 4: 更新config.yaml.example**

```yaml
# CTF-Agent Configuration Example
# 复制此文件为 config.yaml 并填入你的配置

# =============================================================================
# LLM Configuration - 必填
# =============================================================================

# API密钥（必填）
LLM_API_KEY: "your-api-key-here"

# API地址
# DeepSeek: https://api.deepseek.com/v1
# OpenAI: https://api.openai.com/v1
# 阿里云DashScope: https://coding.dashscope.aliyuncs.com/v1
# 智谱: https://open.bigmodel.cn/api/paas/v4
LLM_BASE_URL: "https://api.deepseek.com/v1"

# 统一模型名称
# DeepSeek: deepseek-chat, deepseek-reasoner
# DashScope: qwen-plus, qwen-turbo, qwen-max, qwen-long
# OpenAI: gpt-4o, gpt-4-turbo
LLM_MODEL: "deepseek-chat"

# =============================================================================
# Network Configuration - 内网渗透时需要
# =============================================================================

LOCAL_PUBLIC_IP: ""

# =============================================================================
# Docker Configuration - 默认已启用
# =============================================================================

DOCKER_ENABLED: true
DOCKER_FALLBACK_TO_LOCAL: true

# =============================================================================
# 高级配置 - 按需修改
# =============================================================================

# 超时设置（秒）
# TOOL_TIMEOUT_DEFAULT: 300
# TASK_TIMEOUT: 1800

# 并发设置
# LLM_MAX_CONCURRENT: 10
```

- [ ] **Step 5: 提交配置文件更新**

```bash
git add app/config.py config.yaml config.yaml.example
git commit -m "refactor: 简化配置系统，统一使用LLM_MODEL

- 添加 LLM_MODEL 统一模型配置
- 保留5个Agent模型配置为可选高级设置
- 更新示例配置文件"
```

---

## Task 3: Docker国内源和性能优化

**Files:**
- Modify: `docker/all-in-one/Dockerfile`
- Modify: `docker/base/Dockerfile`
- Optional: 删除其他独立Dockerfile（已被all-in-one替代）

- [ ] **Step 1: 优化all-in-one/Dockerfile添加pip镜像源**

在 `docker/all-in-one/Dockerfile` 中，在pip安装前添加镜像源：

```dockerfile
# pip配置阿里云镜像（在Python工具安装前添加）
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/ && \
    pip config set global.trusted-host mirrors.aliyun.com
```

- [ ] **Step 2: 优化Docker构建添加并行下载**

在 `docker/all-in-one/Dockerfile` 中，优化apt和go安装：

```dockerfile
# 优化apt安装（添加并发下载）
RUN apt-get update && apt-get install -y --no-install-recommends \
    ... \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Go工具并行安装（拆分长命令）
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

- [ ] **Step 3: 添加Docker构建缓存优化**

创建 `.dockerignore` 文件：

```dockerignore
# Git
.git
.gitignore

# Python
__pycache__
*.pyc
*.pyo
*.egg-info
.eggs
*.egg
venv
.venv

# IDE
.idea
.vscode

# Node
node_modules

# Build artifacts
dist
build
*.log

# Data
data/chroma_db
data/rag_cache

# Docker
docker/*/Dockerfile
!docker/all-in-one/Dockerfile
```

- [ ] **Step 4: 更新deploy.sh脚本优化构建参数**

在 `scripts/deploy.sh` 中更新Docker构建命令：

```bash
# 构建all-in-one镜像（优化参数）
docker build \
    --memory=4g \
    --memory-swap=4g \
    --cpus=2 \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    --cache-from ctf-tools:latest \
    -t ctf-tools:latest \
    -f docker/all-in-one/Dockerfile . || log_warn "all-in-one镜像构建失败"
```

- [ ] **Step 5: 提交Docker优化**

```bash
git add docker/all-in-one/Dockerfile docker/base/Dockerfile .dockerignore scripts/deploy.sh
git commit -m "perf: 优化Docker构建

- 添加pip阿里云镜像源
- 添加.dockerignore减少构建上下文
- 优化构建参数使用缓存"
```

---

## Task 4: 删除冗余Dockerfile（可选）

**决策点：** 如果all-in-one已满足需求，可删除独立Dockerfile

- [ ] **评估：检查all-in-one是否包含所有工具**

对比all-in-one与独立Dockerfile的工具覆盖：
- web-tools: nuclei, httpx, sqlmap, fscan, xray, dirsearch ✓
- pwn-tools: pwntools, gdb, ROPgadget ✓
- ad-tools: crackmapexec, impacket, bloodhound, certipy ✓
- misc-tools: binwalk, exiftool ✓
- deser-tools: ysoserial（可能需补充）

- [ ] **如果all-in-one已完整，删除冗余Dockerfile**

```bash
# 保留base和all-in-one，删除其他
rm -rf docker/web-tools docker/pwn-tools docker/ad-tools docker/misc-tools docker/deser-tools
```

- [ ] **提交删除**

```bash
git add -A
git commit -m "chore: 删除冗余Dockerfile，使用all-in-one统一镜像"
```

---

## Verification

### 配置验证
```bash
python -c "from app.config import config; print(f'LLM_MODEL: {config.LLM_MODEL}')"
```

### Docker构建验证
```bash
docker build -t ctf-tools:test -f docker/all-in-one/Dockerfile .
docker run --rm ctf-tools:test nuclei -version
```

### 清理验证
```bash
find . -name "__pycache__" | wc -l  # 应为0
ls app/_archived/  # 应不存在
```