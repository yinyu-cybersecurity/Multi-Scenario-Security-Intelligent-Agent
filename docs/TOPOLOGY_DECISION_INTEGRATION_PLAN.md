# 拓扑-决策对接方案

## 一、问题诊断

### 1.1 当前状态

| 组件 | 状态 | 问题 |
|------|------|------|
| `critical_nodes` 字段 | 已定义 | `state_v2.py:86` 定义，但未被任何节点消费 |
| `find_critical_nodes()` | 已调用 | `explorer_node:1858` 调用，结果存入 state 但未被使用 |
| `prioritize_attack_targets()` | **从未调用** | 关键方法被完全遗漏 |
| `get_attack_surface()` | 从未调用 | 攻击面分析未被利用 |
| `find_hubs()` | 从未调用 | 枢纽节点识别未被利用 |
| `should_explore_more()` | 从未调用 | 探索决策未被智能化 |

### 1.2 影响分析

**问题核心**: 拓扑分析产生的决策情报，从未传递到决策节点。

**具体表现**:
1. `analyst_node`: 无法感知哪些 URL 是关键节点，无法针对关键节点提升分析优先级
2. `attacker_node`: 仅基于 URL 匹配筛选漏洞候选，无法利用拓扑信息调整攻击策略
3. `explorer_node`: 探索顺序随机，未利用 PageRank 排序提升效率
4. `mode_manager_node`: 模式切换决策纯靠失败计数，未考虑拓扑结构

**性能影响**:
- 可能错过高价值攻击路径
- 浪费资源在低价值页面上
- 无法智能判断何时完成探索

---

## 二、对接方案设计

### 2.1 设计原则

1. **非侵入性**: 不改变现有节点的基本流程，只在关键点注入拓扑信息
2. **增量式**: 分层集成，每层独立可测试
3. **可观测性**: 添加日志记录拓扑决策过程
4. **容错性**: 拓扑信息缺失时降级到原有逻辑

### 2.2 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                         State                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ critical_nodes: ['url1', 'url2', ...]                       ││
│  │ site_topology: {url: [neighbor_urls...]}                    ││
│  │ attack_paths: [[url1, url2, target], ...]                   ││
│  │ topology_priority: [(url, score), ...]  ← 新增              ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    消费节点（按优先级）                            │
├─────────────────────────────────────────────────────────────────┤
│ 1. explorer_node: 使用 prioritize_attack_targets() 决定探索顺序  │
│ 2. analyst_node: 使用 critical_nodes 提升关键节点分析优先级       │
│ 3. attacker_node: 使用 topology_priority 调整攻击策略            │
│ 4. mode_manager_node: 使用 should_explore_more() 辅助决策        │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 具体实现方案

#### 方案 A: explorer_node 集成（核心层）

**位置**: `ctf_agent_graph.py:1747` explorer_node 函数

**改动**:
```python
# 在 explorer_node 中，找到攻击路径后，计算优先级
def explorer_node(state: CTFState) -> Dict:
    # ... 现有代码 ...

    # 新增：计算拓扑优先级
    visited_urls = state.get("visited_urls", [])
    priority_targets = analyzer.prioritize_attack_targets(visited_urls, top_k=10)

    # 选择下一个高优先级目标
    if priority_targets:
        next_target = priority_targets[0][0]
        print(f"  🎯 拓扑推荐下一个目标: {next_target} (优先级: {priority_targets[0][1]:.2f})")
    else:
        next_target = None

    return {
        # ... 现有返回值 ...
        "topology_priority": priority_targets,  # 新增
        "next_explore_target": next_target,      # 新增
    }
```

**影响**: 探索节点将智能地选择高 PageRank + 敏感关键词的 URL 作为优先探索目标

#### 方案 B: analyst_node 集成

**位置**: `ctf_agent_graph.py:1013` analyst_node 函数

**改动**: 在构建 prompt 时注入拓扑信息

```python
def analyst_node(state: CTFState) -> Dict:
    # ... 现有代码 ...

    # 新增：获取关键节点信息
    critical_nodes = state.get("critical_nodes", [])
    current_url = state.get("current_url")

    # 判断当前 URL 是否为关键节点
    is_critical = current_url in critical_nodes

    # 在 prompt 中添加拓扑提示
    topology_hint = ""
    if is_critical:
        topology_hint = f"【拓扑分析】当前URL是关键节点（PageRank Top 5），请提升分析深度。"
    elif critical_nodes:
        topology_hint = f"【拓扑分析】已知关键节点: {critical_nodes[:3]}，请关注与这些节点的关联。"

    prompt = get_analyst_prompt(
        # ... 现有参数 ...
        topology_hint=topology_hint  # 新增参数
    )
```

**影响**: 分析节点会针对关键节点进行更深入的分析，避免遗漏高价值目标

#### 方案 C: attacker_node 集成

**位置**: `ctf_agent_graph.py:1462` attacker_node 函数

**改动**: 使用拓扑优先级调整攻击策略

```python
def attacker_node(state: CTFState) -> Dict:
    # ... 现有代码 ...

    # 新增：获取拓扑优先级
    topology_priority = state.get("topology_priority", [])
    priority_dict = {url: score for url, score in topology_priority}

    # 如果当前 URL 是高优先级，增加攻击尝试
    current_priority = priority_dict.get(current_url, 0.5)

    # 在 candidates 排序时加入拓扑权重
    candidates = [c for c in all_candidates if c.get("url") == current_url]
    # 按拓扑优先级 + 置信度排序
    candidates.sort(key=lambda c: (
        c.get("confidence", 0) * 0.6 + priority_dict.get(c.get("url", ""), 0.5) * 0.4
    ), reverse=True)

    # 根据优先级动态调整攻击动作数量
    max_actions = 15 if current_priority > 0.7 else 10
```

**影响**: 高价值节点将获得更多攻击资源和更精细的策略

#### 方案 D: mode_manager_node 集成

**位置**: `ctf_agent_graph.py:1135` mode_manager_node 函数

**改动**: 使用 should_explore_more() 辅助决策

```python
def mode_manager_node(state: CTFState) -> Dict:
    # ... 现有代码 ...

    # 新增：拓扑探索判断
    try:
        G = nx.DiGraph(state.get("site_topology", {}))
        if G.number_of_nodes() > 0:
            analyzer = TopologyAnalyzer(G)
            visited_urls = state.get("visited_urls", [])

            # 是否还有高价值未探索节点
            has_high_value = analyzer.should_explore_more(visited_urls, threshold=0.3)

            if not has_high_value and score < 3.0:
                # 拓扑显示无高价值节点，且失败分数不高，可能已穷尽
                # 切换到创新模式而非继续探索
                return {
                    "current_mode": "innovate",
                    "execution_steps": state.get("execution_steps", 0) + 1
                }
    except Exception as e:
        logger.warning(f"拓扑分析失败: {e}")

    # ... 现有逻辑 ...
```

**影响**: 模式切换将更智能，避免无意义的探索循环

---

## 三、实现步骤

### 阶段 1: 基础集成（优先级：高）

| 步骤 | 文件 | 改动内容 | 预估行数 |
|------|------|----------|----------|
| 1.1 | state_v2.py | 添加 `topology_priority` 字段 | +2 行 |
| 1.2 | ctf_agent_graph.py | explorer_node 调用 `prioritize_attack_targets()` | +15 行 |
| 1.3 | ctf_agent_graph.py | explorer_node 返回 `topology_priority` | +5 行 |

### 阶段 2: 分析集成（优先级：中）

| 步骤 | 文件 | 改动内容 | 预估行数 |
|------|------|----------|----------|
| 2.1 | prompts.py | `get_analyst_prompt()` 添加 `topology_hint` 参数 | +5 行 |
| 2.2 | ctf_agent_graph.py | analyst_node 注入拓扑提示 | +10 行 |

### 阶段 3: 攻击集成（优先级：中）

| 步骤 | 文件 | 改动内容 | 预估行数 |
|------|------|----------|----------|
| 3.1 | ctf_agent_graph.py | attacker_node 使用拓扑优先级排序 | +10 行 |
| 3.2 | ctf_agent_graph.py | attacker_node 动态调整攻击数量 | +5 行 |

### 阶段 4: 模式决策集成（优先级：低）

| 步骤 | 文件 | 改动内容 | 预估行数 |
|------|------|----------|----------|
| 4.1 | ctf_agent_graph.py | mode_manager_node 使用 `should_explore_more()` | +15 行 |

---

## 四、风险评估与缓解

### 4.1 风险矩阵

| 风险 | 可能性 | 影响 | 缓解措施 |
|------|--------|------|----------|
| 拓扑数据为空导致崩溃 | 中 | 高 | 所有调用添加 try-except，缺失时降级 |
| PageRank 计算性能问题 | 低 | 中 | 节点数 >100 时采样计算 |
| 拓扑信息误导决策 | 低 | 中 | 仅作辅助权重，不覆盖核心逻辑 |
| 状态字段膨胀 | 低 | 低 | `topology_priority` 限制最多 10 个 |

### 4.2 降级策略

```python
# 所有拓扑集成点都应包含降级逻辑
def safe_topology_call(analyzer, method_name, default_value, *args):
    try:
        method = getattr(analyzer, method_name)
        return method(*args)
    except Exception as e:
        logger.warning(f"拓扑分析失败 [{method_name}]: {e}")
        return default_value
```

---

## 五、验证方案

### 5.1 单元测试

```python
def test_topology_priority_in_explorer():
    """测试 explorer_node 正确计算并返回拓扑优先级"""
    state = {
        "target_url": "http://example.com",
        "site_topology": {"url1": ["url2"], "url2": ["url3"], "url3": []},
        "visited_urls": ["url1"]
    }
    result = explorer_node(state)
    assert "topology_priority" in result
    assert len(result["topology_priority"]) > 0

def test_critical_nodes_in_analyst():
    """测试 analyst_node 正确注入关键节点提示"""
    state = {
        "current_url": "http://example.com/login",
        "critical_nodes": ["http://example.com/login", "http://example.com/admin"],
        # ... 其他字段
    }
    # 验证 prompt 中包含关键节点信息
```

### 5.2 集成测试

1. **端到端测试**: 运行完整 CTF 任务，验证拓扑信息在各节点间正确传递
2. **性能测试**: 对比集成前后的探索效率（找到 flag 的时间/步数）
3. **回归测试**: 确保现有功能不受影响

---

## 六、预期收益

| 指标 | 改进预期 |
|------|----------|
| 探索效率 | 提升 20-40%（优先访问高价值节点） |
| 攻击精准度 | 提升 15-25%（关键节点获得更多资源） |
| 模式切换准确性 | 提升 10-20%（智能判断探索穷尽） |
| 资源利用率 | 降低 15%（减少无效探索） |

---

## 七、执行计划

### 执行顺序

1. **立即执行**: 阶段 1（基础集成）- 确保拓扑优先级可传递
2. **次优先**: 阶段 2（分析集成）- 提升分析质量
3. **并行执行**: 阶段 3（攻击集成）- 提升攻击效率
4. **最后执行**: 阶段 4（模式决策）- 优化整体流程

### 验收标准

- [ ] `prioritize_attack_targets()` 被正确调用
- [ ] `topology_priority` 字段在 state 中正确传递
- [ ] analyst_node 的 prompt 包含拓扑信息
- [ ] attacker_node 使用拓扑优先级排序
- [ ] 所有改动添加了适当的错误处理
- [ ] 无回归问题

---

## 八、总结

本方案通过四层集成，将拓扑分析产生的决策情报传递到各个决策节点。核心思路是：

1. **explorer_node** 负责生产拓扑情报（优先级列表）
2. **analyst_node** 和 **attacker_node** 消费拓扑情报（调整策略）
3. **mode_manager_node** 使用拓扑情报辅助决策

通过这种"生产者-消费者"模式，在不破坏现有架构的前提下，实现拓扑与决策的深度融合。