# CTF-Agent 2.0 集成迁移计划

## 一、迁移策略：渐进式三阶段

### Phase 1: 基础设施（已完成 ✅）
- [x] Agent类型系统
- [x] Memory系统
- [x] Prompt Cache
- [x] Selector Store
- [x] State V3
- [x] buildTool工厂
- [x] Coordinator调度器
- [x] 智能压缩器

### Phase 2: 功能迁移（当前阶段）
- [ ] 迁移工具到ToolRegistryV2
- [ ] 集成Serena MCP客户端
- [ ] 重构LangGraph状态机
- [ ] 实现Agent执行引擎
- [ ] CLI界面开发

### Phase 3: 清理与优化
- [ ] 删除旧模块
- [ ] 更新文档
- [ ] 性能优化
- [ ] 测试覆盖

---

## 二、旧模块处理策略

### 保留并迁移

| 旧模块 | 新模块 | 迁移策略 |
|--------|--------|----------|
| `app/tools/` | `app/tools_v2/` | 逐个工具重写，使用buildTool |
| `app/graph/` | `app/graph_v2/` | 重构为StateGraph |
| `app/nodes/` | 合并到 `app/agents/` | 节点逻辑转为Agent方法 |
| `app/prompts/` | 保留，优化 | Prompt模板优化 |

### 删除计划

```python
# Phase 3 删除清单（Phase 2 完成后执行）

# 1. 备份旧模块
git checkout -b backup/old-modules
git add app/tools/ app/nodes/ app/state_types/
git commit -m "backup: 旧模块备份"

# 2. 切回主分支删除
git checkout main
git rm -r app/tools/ app/nodes/ app/state_types/
git commit -m "refactor: 删除旧模块，迁移完成"

# 3. 更新导入
# 全局搜索替换导入路径
```

### 并行运行期

```python
# 允许新旧模块共存
# app/__init__.py

# 新架构（优先）
from app.tools_v2 import get_tool_registry_v2
from app.state import get_selector_store

# 旧架构（兼容）
from app.tools import ToolRegistry  # 将废弃
from app.graph import CTFGraph      # 将废弃
```

---

## 三、代码规范

### 3.1 文件头部注释

```python
# 模块名称 - 一行描述
#
# 详细说明（可选）
#
# 借鉴来源（如果有）

"""
示例：
# Agent类型系统 - 定义5类Agent及权限边界
#
# 借鉴Claude Code的分层Agent架构设计
"""
```

### 3.2 类注释规范

```python
class ClassName:
    """
    类的简短描述
    
    借鉴来源（如果有）:
    - Claude Code: XXX设计
    - LangGraph: YYY模式
    
    核心功能:
    1. 功能1
    2. 功能2
    
    使用示例:
        obj = ClassName()
        result = obj.method()
    """
```

### 3.3 方法注释规范

```python
def method_name(
    self,
    param1: Type1,
    param2: Type2
) -> ReturnType:
    """
    方法简短描述
    
    Args:
        param1: 参数1说明
        param2: 参数2说明
    
    Returns:
        返回值说明
    
    Raises:
        ExceptionType: 异常说明
    
    Example:
        result = obj.method_name(param1, param2)
    """
```

### 3.4 类型注解规范

```python
from typing import Dict, List, Optional, Any, Callable

# 必须使用类型注解
def process_data(
    data: Dict[str, Any],
    callback: Optional[Callable[[Dict], None]] = None
) -> List[Dict]:
    """处理数据"""
    pass

# 使用dataclass定义数据结构
@dataclass
class DataModel:
    """数据模型"""
    field1: str
    field2: int = 0
    field3: Optional[List[str]] = None
```

---

## 四、接口规范

### 4.1 Agent接口

```python
from abc import ABC, abstractmethod

class BaseAgent(ABC):
    """Agent基类接口"""
    
    @abstractmethod
    async def execute(
        self,
        task: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        执行Agent任务
        
        Args:
            task: 任务描述
            context: 执行上下文（包含state、memory等）
        
        Returns:
            {
                "success": bool,
                "findings": List[Dict],
                "tool_calls": List[Dict],
                "next_phase": Optional[str]
            }
        """
        pass
    
    @abstractmethod
    def get_allowed_tools(self) -> List[str]:
        """获取允许的工具列表"""
        pass
```

### 4.2 Tool接口

```python
class CTFToolV2:
    """工具接口（已实现）"""
    
    async def execute(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any],
        agent_type: AgentType
    ) -> ToolExecutionResult:
        """执行工具"""
        pass
    
    def get_schema_dict(self) -> Dict:
        """获取工具Schema"""
        pass
```

### 4.3 Memory接口

```python
class MemoryInterface(ABC):
    """Memory系统接口"""
    
    @abstractmethod
    async def write(
        self,
        name: str,
        content: str,
        topic: str = ""
    ) -> bool:
        """写入Memory"""
        pass
    
    @abstractmethod
    async def read(self, name: str) -> Optional[str]:
        """读取Memory"""
        pass
    
    @abstractmethod
    async def list(self, topic: str = "") -> List[str]:
        """列出Memory"""
        pass
```

---

## 五、迁移执行清单

### 5.1 Phase 2 任务分解

```
[ ] 1. 工具迁移
    [ ] 1.1 分析现有工具列表
    [ ] 1.2 为每个工具创建buildTool定义
    [ ] 1.3 迁移工具Handler
    [ ] 1.4 注册到ToolRegistryV2
    [ ] 1.5 测试工具执行

[ ] 2. Serena集成
    [ ] 2.1 初始化Serena客户端
    [ ] 2.2 连接到Memory系统
    [ ] 2.3 测试Memory读写
    [ ] 2.4 实现Agent间通信

[ ] 3. 状态机重构
    [ ] 3.1 设计StateGraph
    [ ] 3.2 实现节点函数
    [ ] 3.3 定义边和条件
    [ ] 3.4 测试状态流转

[ ] 4. Agent执行引擎
    [ ] 4.1 实现BaseAgent
    [ ] 4.2 实现各Agent子类
    [ ] 4.3 集成工具调用
    [ ] 4.4 测试Agent执行

[ ] 5. CLI开发
    [ ] 5.1 设计命令系统
    [ ] 5.2 实现REPL循环
    [ ] 5.3 实现输出格式化
    [ ] 5.4 测试CLI交互
```

### 5.2 Phase 3 清理清单

```
[ ] 1. 代码清理
    [ ] 1.1 删除app/tools/
    [ ] 1.2 删除app/nodes/
    [ ] 1.3 删除app/state_types/
    [ ] 1.4 更新所有导入

[ ] 2. 文档更新
    [ ] 2.1 更新README.md
    [ ] 2.2 更新CLAUDE.md
    [ ] 2.3 删除过时文档
    [ ] 2.4 添加新文档

[ ] 3. 测试覆盖
    [ ] 3.1 单元测试
    [ ] 3.2 集成测试
    [ ] 3.3 性能测试
    [ ] 3.4 E2E测试
```

---

## 六、风险控制

### 6.1 回滚策略

```bash
# 创建迁移标签
git tag -a v2.0-phase1 -m "Phase 1 完成"
git tag -a v2.0-phase2 -m "Phase 2 完成"

# 如果出现问题，回滚
git checkout v2.0-phase1
```

### 6.2 兼容性检查

```python
# 每次迁移后运行兼容性测试
def test_compatibility():
    # 测试新工具系统
    registry = get_tool_registry_v2()
    assert len(registry.list_tools()) > 0
    
    # 测试新状态系统
    store = get_selector_store()
    state = create_initial_state(challenge)
    assert store is not None
    
    # 测试Memory系统
    memory = get_memory_system()
    assert memory is not None
```

---

## 七、时间估算

| Phase | 任务 | 预计时间 |
|-------|------|----------|
| Phase 2.1 | 工具迁移 | 2-3天 |
| Phase 2.2 | Serena集成 | 1天 |
| Phase 2.3 | 状态机重构 | 2天 |
| Phase 2.4 | Agent执行引擎 | 2天 |
| Phase 2.5 | CLI开发 | 2天 |
| Phase 3 | 清理优化 | 2天 |
| **总计** | | **约11-12天** |

---

## 八、验收标准

### Phase 2 完成标准
- [ ] 所有工具迁移到ToolRegistryV2
- [ ] Serena Memory正常工作
- [ ] LangGraph状态机运行正常
- [ ] Agent能成功执行任务
- [ ] CLI能交互使用

### Phase 3 完成标准
- [ ] 旧模块已删除
- [ ] 测试覆盖率 > 70%
- [ ] 文档更新完成
- [ ] 性能基准通过