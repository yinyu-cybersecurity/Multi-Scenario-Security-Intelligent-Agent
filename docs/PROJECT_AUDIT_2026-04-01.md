# 项目详细审计报告

审计时间：2026-04-01  
审计分支：`doc/project-audit-agents`  
审计方式：静态代码审查 + 轻量级测试验证  

---

## 1. 审计范围

本次审计重点覆盖：

- `README.md`
- `requirements.txt`
- `web/api.py`
- `app/tool_framework.py`
- `app/ctf_agent_graph.py`
- `remote_executor/session_manager.py`
- `internal_network/credential_manager.py`
- `tools/__init__.py`
- `tools/python_exec_tool.py`
- `tools/file_creator_tool.py`
- `tests/`
- `.github/workflows/ci.yml`

未进行内容：

- 未对外部目标站点做动态攻击测试
- 未对所有第三方工具逐一联调
- 未下载额外依赖后进行全量集成验证

---

## 2. 项目总体判断

这是一个能力很强、边界也很危险的仓库。

优点：

- 模块拆分相对清晰，核心流、工具层、远程执行层、Web 层基本分区明确
- 文档较多，项目意图、路线和能力边界比普通仓库更清楚
- 已有一定测试和 CI 骨架，不是完全裸奔状态

主要问题：

- 管理面默认暴露过大
- 宿主机级能力没有被真正隔离
- 会话与凭据处理缺少最基本的保护
- 测试与 CI 的可信度不足
- 工具注册接口已出现实现与测试、脚本、调用方三方漂移

结论：

> 当前仓库更像“研究/竞赛环境中的高权限安全代理”，还不能把默认配置视为可直接暴露或可安全协作的生产基线。

---

## 3. 关键发现

### 3.1 Critical: Web 控制面无认证、全局开放 CORS、默认监听 `0.0.0.0`

证据：

- `web/api.py:80` 直接 `CORS(app)`
- `web/api.py:1305-1353` 允许任意请求启动任务
- `web/api.py:1544-1550` 允许直接读取任务结果
- `web/api.py:2352-2410` 允许读取与修改运行时配置
- `web/api.py:2772-2786` 默认监听 `0.0.0.0:54565`

影响：

- 任意能访问该端口的人都可以发起代理任务
- 任意人都可以读取任务结果，结果中可能包含 `flag`、凭据、内网主机信息等敏感数据
- 任意人都可以运行时修改 `LLM_BASE_URL`、`LLM_API_KEY` 等关键配置
- 开放 CORS 使得第三方站点能直接从浏览器发起跨站调用，不需要后端代理

风险等级：最高

建议：

1. 默认绑定 `127.0.0.1`
2. 所有 `/api/*` 加鉴权与鉴权失败审计日志
3. 默认关闭 CORS，改为显式 allowlist
4. 将“启动任务”“读取结果”“修改配置”“查看 session”分级授权

---

### 3.2 High: 会话密码和 SSH 私钥明文持久化到 `data/sessions.json`

证据：

- `remote_executor/session_manager.py:96-101` `ShellSession` 直接持有 `password` / `private_key`
- `remote_executor/session_manager.py:103-107` `to_dict()` 直接序列化整个会话对象
- `remote_executor/session_manager.py:262-281` 会话被加载/保存到 `data/sessions.json`
- `remote_executor/session_manager.py:369-378` 创建 SSH 会话时直接把密码/私钥塞进会话对象

影响：

- 主机一旦被低权限读取或日志/备份误打包，凭据直接泄露
- 如果 `data/sessions.json` 被误提交、误同步、误挂载，风险进一步扩大
- 该问题和仓库本身“高危工具丰富”的特点叠加后，属于高价值秘密集中点

建议：

1. 默认不落盘凭据
2. 如必须持久化，至少对敏感字段做加密或改为外部 secret store
3. 明确把 `data/sessions.json` 加入忽略列表并在启动时检测

---

### 3.3 High: SSH 主机指纹校验被显式关闭

证据：

- `remote_executor/session_manager.py:495-496`
- `remote_executor/session_manager.py:520-521`
- `internal_network/credential_manager.py:798-799`

问题：

- 代码统一使用 `paramiko.AutoAddPolicy()`
- 这会接受未知主机指纹，相当于默认信任任意 SSH 服务端

影响：

- 在真实内网、跳板或不可信网络环境中容易遭受 MITM
- 一旦被中间人接管，后续命令、密码、私钥探测都可能被劫持

建议：

1. 默认改为 Reject Policy
2. 增加已知主机文件和显式信任开关
3. 仅在明确的竞赛/靶机场景下允许关闭校验，且必须显式标志

---

### 3.4 High: 核心工具默认带宿主机执行与写文件能力，但没有隔离边界

证据：

- `tools/__init__.py:18-23` 核心工具包含 `python_exec_tool`、`file_creator_tool`
- `app/ctf_agent_graph.py:3680-3682` 启动时加载最小工具集
- `tools/python_exec_tool.py:441-452` 明确对外宣称可执行 Python 脚本
- `tools/python_exec_tool.py:1000-1005` `env_exec_cmd()` 使用 `shell=True`
- `tools/file_creator_tool.py:93-131` 任意根据参数创建文件
- `tools/file_creator_tool.py:411-421` 以未净化的 `filename` / `ext` 直接拼路径

影响：

- 该代理处理的是不可信目标内容、网页返回、工具输出和 LLM 生成内容
- 在当前设计下，只要策略/提示被绕过，就可能把“分析目标”升级成“在宿主机执行命令或写文件”
- `file_creator_tool` 还存在相对路径穿越风险，例如通过 `../` 逃逸出 `data/tool_outputs`

说明：

- 这是“架构级风险”，不只是单个 bug
- 在研究/竞赛环境中可能是有意设计，但必须被视为高危运行模式，而不是默认安全基线

建议：

1. 默认禁用高危本地执行工具，改为按模式显式开启
2. 给 `python-exec` 加强沙箱，至少禁止 `shell=True`
3. 给 `file-creator` 加路径白名单和文件名净化
4. 在 UI / CLI 明确标注“将执行宿主机能力”的警告

---

### 3.5 Medium: SSH 私钥验证分支存在明显实现错误

证据：

- `internal_network/credential_manager.py:808-810`

问题：

- `paramiko.RSAKey.from_private_key_file(io.StringIO(cred.ssh_key))` 调用了错误 API
- `from_private_key_file()` 需要文件路径，不是 `StringIO`
- 这意味着内存中的私钥验证逻辑大概率会抛异常或始终失败

影响：

- SSH 密钥型凭据可能被错误判定为无效
- 会影响自动化验证与后续攻击链规划

建议：

1. 如果是字符串内容，改用 `from_private_key()`
2. 如果是文件路径，再用 `from_private_key_file()`
3. 为密码分支和私钥分支各补一条单元测试

---

### 3.6 Medium: 测试与 CI 当前不能可靠阻止回归

证据：

- `requirements.txt` 未声明 `networkx` / `matplotlib` / `pyvis`
- `app/topology/visualizer.py:4-5, 55` 直接依赖这些包
- `tests/test_topology_viz.py:4` 测试收集就依赖 `networkx`
- `.github/workflows/ci.yml:47` `pip install -r requirements.txt || true`
- `.github/workflows/ci.yml:52` `pytest ... || echo "No tests yet"`

本地验证结果：

- `pytest -q`：
  - 失败，原因：`ModuleNotFoundError: No module named 'networkx'`
- `pytest -q tests/test_tool_framework.py tests/test_state_types.py`：
  - 结果：`7 failed, 30 passed`

影响：

- 依赖缺失不会让 CI 失败
- 测试失败也不会让 CI 失败
- 当前 CI 只能证明“命令跑过”，不能证明“仓库健康”

建议：

1. 新增 `requirements-dev.txt` 或统一到 `pyproject.toml`
2. 去掉 CI 中吞错逻辑
3. 把拓扑相关依赖补全
4. 将“单元测试失败 == CI 失败”恢复为硬约束

---

### 3.7 Medium: 工具注册接口已经出现实现漂移，测试和验证脚本被打断

证据：

- `tools/__init__.py:137-183` 只有调用 `_ensure_tools_loaded()` / `load_*` 才会真正加载工具
- `verify_system.py:53-55` 仍然把 `import tools` 当成“触发自动注册”
- `app/tool_framework.py:764-766` 第一版 `get_tool_names()` 返回 `List[str]`
- `app/tool_framework.py:871-903` 后面又定义了第二版 `get_tool_names()`，返回 `str`

影响：

- 测试中的“导入即注册”假设已经失效
- `get_tool_names()` 的返回类型被后定义覆盖，破坏了旧测试和可能的旧调用方
- 这不是单纯的测试问题，而是公共接口已经不稳定

建议：

1. 统一 `ToolRegistry` 的公共 API，不要在同一类里重复定义同名方法
2. 明确“导入即注册”还是“显式加载”这一个约定
3. 修复 `verify_system.py` 与测试，让它们跟当前设计一致

---

## 4. 验证记录

执行命令：

```bash
git status --short --branch
pytest -q
pytest -q tests/test_tool_framework.py tests/test_state_types.py
```

结果摘要：

- 当前工作分支：`doc/project-audit-agents`
- `pytest -q` 因拓扑依赖缺失中断
- 去掉拓扑测试后，工具注册相关测试仍失败

---

## 5. 优先整改顺序

建议按以下顺序处理：

1. 锁住 Web 管理面
2. 停止明文持久化凭据并恢复 SSH 指纹校验
3. 收紧高危本地执行/写文件工具的默认暴露面
4. 修复 ToolRegistry 公共接口漂移
5. 修复依赖声明与 CI 吞错

---

## 6. 适合立刻落地的最小修复包

如果只做一轮最小但高价值的修复，建议包含：

- 给 `web/api.py` 加认证中间件
- 默认改成监听 `127.0.0.1`
- `CORS(app)` 改为可配置 allowlist
- 删除会话落盘中的 `password` / `private_key`
- SSH 改为显式主机校验
- 修复 `credential_manager` 私钥验证
- CI 去掉 `|| true` 和 `|| echo`

---

## 7. 审计结论

仓库的核心能力没有问题，问题在于：

- 它已经具备“攻防平台”的能力
- 但管理面、安全边界、秘密保护和回归验证还停留在研究环境习惯

如果继续以当前默认方式运行，本仓库最容易出现的不是“功能用不了”，而是：

- 被未授权用户接管任务控制面
- 凭据与私钥被明文泄露
- 不可信输入借由 Agent 能力放大成宿主机风险
- 回归被 CI 漏检

因此，本仓库当前更适合：

- 本地研究
- 内部隔离环境
- 受控竞赛环境

不适合直接作为无额外防护的公网服务或多人共享高权限平台。
