# 贡献指南

## 开发工作流

### 1. Fork & Clone
```bash
# Fork 后克隆你的仓库
git clone https://github.com/<your-username>/ctf-agent.git
cd ctf-agent

# 添加上游仓库
git remote add upstream https://github.com/<org>/ctf-agent.git
```

### 2. 创建分支
```bash
# 从 main 创建功能分支
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name
```

分支命名规范：
- `feature/xxx` - 新功能
- `fix/xxx` - Bug 修复
- `docs/xxx` - 文档更新
- `refactor/xxx` - 代码重构

### 3. 提交代码
```bash
git add .
git commit -m "feat: add xxx feature"
```

Commit 规范 (Conventional Commits):
- `feat:` 新功能
- `fix:` Bug 修复
- `docs:` 文档
- `style:` 格式调整
- `refactor:` 重构
- `test:` 测试
- `chore:` 构建/工具

### 4. 推送并创建 PR
```bash
git push origin feature/your-feature-name
```

然后在 GitHub 上创建 Pull Request。

### 5. Code Review
- 至少需要 **1 个 Reviewer** 批准
- 通过所有 CI 检查
- 解决所有 Review 意见后才能合并

### 6. 合并
- 使用 **Squash and merge** 保持提交历史整洁
- 删除功能分支

---

## 代码规范

### Python
- 使用 `black` 格式化
- 使用 `isort` 排序 imports
- 使用 `mypy` 类型检查
- 使用 `ruff` linting

```bash
# 安装开发依赖
pip install -r requirements-dev.txt

# 格式化
black .
isort .

# 检查
ruff check .
mypy .
```

### 测试
```bash
# 运行测试
pytest tests/ -v --cov=app

# 测试覆盖率要求 > 60%
```

---

## 项目结构

```
ctf-agent/
├── app/                    # 主应用代码
│   ├── ctf_agent_graph.py  # 主图定义
│   ├── state.py            # 状态定义
│   ├── router.py           # 路由逻辑
│   └── ...
├── tools/                  # 工具实现
├── internal_network/       # 内网渗透模块
├── crypto/                 # Crypto 模块
├── tests/                  # 测试文件
├── docs/                   # 文档
└── deploy/                 # 部署配置
```

---

## Issue 模板

提交 Issue 时请包含：
1. **描述**: 清晰描述问题或需求
2. **复现步骤** (Bug): 如何复现
3. **期望行为**: 应该怎样
4. **实际行为**: 实际怎样
5. **环境**: OS, Python 版本等