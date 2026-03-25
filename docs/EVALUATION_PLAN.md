# CTF-Agent 项目评估与优化计划

## 一、问题清单状态

### 1. 前端问题
- [x] 工具数量显示为0（ToolRegistry访问方式错误） - 已修复
- [x] 导航按钮位置不固定，会随点击乱跑 - 已修复
- [x] 节点拆卸功能未实现 - 已实现
- [x] 节点图显示混乱 - 已修复（按分组排序，添加groupName字段）

### 2. 功能对接问题（重要发现）
- [x] **拓扑图与决策未对接** - 已修复
  - `critical_nodes` 现在被 `analyst_node` 使用
  - `topology_priority` 字段已添加并传递
  - `attacker_node` 使用拓扑优先级排序
- [x] **`prioritize_attack_targets()`未调用** - 已修复
  - 在 `explorer_node` 中调用
  - 返回 `topology_priority` 供其他节点使用
- [x] **攻击节点选择逻辑简单** - 已优化
  - 现在使用拓扑优先级 + 置信度综合排序
  - 高优先级目标增加攻击动作上限

### 3. 上下文传递检查
- [x] 状态压缩时机合理（router.py:129）
- [x] CRITICAL字段完整保留
- [x] 状态更新无遗漏（拓扑字段已添加）

### 4. 代码质量问题
- [x] 无过时标记（【任务X.X】等已清理）
- [x] 注释已统一为中文
- [x] print 已替换为 logger（支持分任务、分节点日志）

### 5. 节点排序优化
- [x] 节点按执行流程排序：入口 → Web主流程 → 内网 → 其他分支 → 结束

### 6. 异常处理优化
- [x] 修复裸 `except:` 问题（改为 `except Exception` 或具体异常类型）
- [x] 保持错误记录但继续运行

### 7. 性能监控
- [x] 添加性能监控面板API
- [x] 节点执行耗时统计
- [x] LLM调用耗时统计
- [x] 工具执行耗时统计
- [x] 慢操作检测

---

## 二、已完成修复

### 2026-03-25 修复记录

1. **前端导航栏固定**
   - 所有模板添加 `position: fixed` 和 `z-index: 100`
   - body 添加 `padding-top: 56px`

2. **工具数量显示修复**
   - 修复 `ToolRegistry._tools` 访问错误
   - 使用 `ToolRegistry.get_all_tools()` 和 `get_statistics()`
   - API启动时导入tools模块触发注册

3. **节点拆卸功能实现**
   - 添加 `node_enabled` 全局状态存储
   - 添加 `/api/nodes/<node_id>/toggle` API端点
   - 修改 `get_graph_structure()` 根据节点状态过滤边
   - 前端添加节点启用/禁用按钮

### 2026-03-25 拓扑-决策对接

1. **state_v2.py 更新**
   - 添加 `topology_priority: List[tuple]` 字段
   - 存储格式: `[(url, score), ...]`

2. **explorer_node 更新**
   - 调用 `prioritize_attack_targets()` 计算拓扑优先级
   - 返回 `topology_priority` 供其他节点消费
   - 输出优先目标日志

3. **analyst_node 更新**
   - 获取 `critical_nodes` 和 `topology_priority`
   - 构建 `topology_hint` 注入到 prompt
   - 关键节点提示提升分析深度

4. **attacker_node 更新**
   - 使用拓扑优先级排序漏洞候选
   - 高优先级目标增加攻击动作上限
   - 传递 `topology_priority` 到 task_info

---

## 三、架构文档

详细对接方案参见:
- `docs/TOPOLOGY_DECISION_INTEGRATION_PLAN.md` - 拓扑决策对接方案
- `docs/TOPOLOGY_EVALUATION_REPORT.md` - 方案评估报告

---

## 四、死循环检测验证

router.py 中的 RouteGuard 实现了完善的死循环检测:
1. 同一节点连续访问 > 10 次触发
2. A→B→A 来回循环检测（6次以上）
3. 600秒无进展检测

检测结果: ✅ 通过

---

## 五、后续优化建议

### 低优先级
1. 将调试 print 改为 logger.debug()
2. 添加拓扑分析性能监控
3. 敏感关键词移至配置文件