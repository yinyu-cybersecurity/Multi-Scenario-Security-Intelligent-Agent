# CTF-Agent 2.0 重构核心原则

## 1. Agent类型系统 (借鉴Claude Code)

### 五类Agent
- **Explore**: 只读，glm-5，信息收集
- **Plan**: 只读，glm-5，攻击策略规划
- **Attack**: 读写执行，glm-5，漏洞利用
- **Verify**: 读写执行，glm-5，结果验证
- **Coordinator**: 只读，glm-5，多Agent协调

## 2. Prompt Cache共享机制
- Fork子Agent继承父Agent完整历史
- 为tool_use创建占位结果确保缓存命中
- 并行扫描多个目标时共享上下文

## 3. Selector模式状态管理
- 细粒度订阅状态切片
- 避免全量状态传递

## 4. 智能工具调用
- Zod Schema验证
- 权限检查分离
- 并发安全标记

## 5. 上下文压缩优先级
- CRITICAL: 凭据、FLAG、Shell会话
- HIGH: 漏洞、攻击链、内网资产
- MEDIUM: 扫描结果
- LOW: 工具调用日志