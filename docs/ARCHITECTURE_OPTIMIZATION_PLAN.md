# 架构优化计划

## 评估摘要
- 综合评分: 6.75/10
- 当前阶段: 开发阶段 (80%)
- 主要瓶颈: 状态管理臃肿、测试覆盖不足

---

## P0 级改进（必须完成）

### 任务 1: 修复工具自动注册
**问题**: ToolRegistry._tools 为空，46 个工具未注册
**工作量**: 低
**修改文件**: tools/__init__.py

**方案**:
```python
# tools/__init__.py
from tool_framework import ToolRegistry

# 自动导入并注册所有工具
import os
import importlib

_tool_modules = [
    'nmap_tool', 'fscan_tool', 'sqlmap_tool', 'nuclei_scanner',
    'ffuf_tool', 'dirsearch_tool', 'hydra_tool', 'impacket_tool',
    # ... 其他工具模块
]

for module_name in _tool_modules:
    try:
        module = importlib.import_module(f'.{module_name}', package='tools')
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and hasattr(attr, 'execute'):
                ToolRegistry.register(attr())
    except ImportError:
        pass
```

---

### 任务 2: 完成 state_types 迁移
**问题**: state.py 仍有 94 个字段，state_types/ 未被使用
**工作量**: 高
**修改文件**:
- app/state.py（重构为导出接口）
- app/ctf_agent_graph.py（更新导入）
- 各节点文件（更新状态访问）

**方案**:
```
阶段 A: 创建组合状态类
├── CTFState = WebCTFState + InternalNetworkState + CryptoCTFState + ...
└── 保持向后兼容

阶段 B: 更新节点代码
├── 将 state['xxx'] 访问改为类型化访问
└── 添加类型检查

阶段 C: 废弃旧 state.py
├── state.py 只保留导出
└── 所有定义移到 state_types/
```

---

## P1 级改进（重要）

### 任务 3: 添加 pytest 单元测试
**问题**: 无单元测试框架
**工作量**: 中
**新增文件**: tests/

**测试范围**:
```
tests/
├── test_state_types.py    # 状态类型测试
├── test_reducers.py       # 规约器测试
├── test_module_registry.py # 模块注册测试
├── test_tool_framework.py  # 工具框架测试
├── test_llm_client.py      # LLM 客户端测试
└── test_tools/
    ├── test_nmap_tool.py
    └── test_fscan_tool.py
```

---

### 任务 4: 统一 AI Prompt 管理
**问题**: Prompt 分散在多个文件
**工作量**: 中
**新增文件**: app/prompts/

**方案**:
```
app/prompts/
├── __init__.py
├── analyst.py      # 分析兵 prompt
├── attacker.py     # 攻击兵 prompt
├── verifier.py     # 核验兵 prompt
├── innovator.py    # 创新模式 prompt
└── internal.py     # 内网渗透 prompt
```

---

## P2 级改进（优化）

### 任务 5: 添加性能监控
**问题**: 无执行时间追踪
**工作量**: 中
**修改文件**: app/performance.py

**指标**:
- 节点执行时间
- LLM Token 消耗
- 工具调用统计
- 状态大小变化

---

### 任务 6: 完善开发文档
**问题**: 缺少 API 文档
**工作量**: 低
**新增文件**: docs/

**内容**:
- API_REFERENCE.md
- DEVELOPMENT_GUIDE.md
- CONTRIBUTING.md

---

## 执行顺序

```
Week 1: P0 任务
├── Day 1-2: 任务 1 - 工具自动注册
└── Day 3-5: 任务 2 阶段 A - 创建组合状态类

Week 2: P0 任务 + P1 开始
├── Day 1-3: 任务 2 阶段 B - 更新节点代码
├── Day 4-5: 任务 3 - 添加测试框架

Week 3: P1 任务
├── Day 1-3: 任务 4 - Prompt 管理
└── Day 4-5: 任务 2 阶段 C - 废弃旧文件

Week 4: P2 任务
├── Day 1-3: 任务 5 - 性能监控
└── Day 4-5: 任务 6 - 文档完善
```

---

## 验收标准

| 任务 | 验收标准 |
|------|----------|
| 任务 1 | len(ToolRegistry._tools) > 0 |
| 任务 2 | CTFState 字段数 < 50，类型化访问 |
| 任务 3 | pytest 通过率 > 80% |
| 任务 4 | 所有 prompt 集中在 prompts/ |
| 任务 5 | 性能数据可查询 |
| 任务 6 | 文档覆盖核心 API |