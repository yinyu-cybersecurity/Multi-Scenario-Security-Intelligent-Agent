# CTF-Agent 2.0 前端界面设计文档

**日期**: 2026-04-01
**版本**: 1.0
**技术栈**: React 18 + TypeScript + Tailwind CSS + Vite

---

## 一、设计理念

### 1.1 核心原则

- **实时反馈**: 展示Agent执行进度、工具调用、状态变化
- **可视化**: 攻击树状图、网络拓扑、Token统计
- **交互式**: 支持用户干预、策略调整、手动验证
- **专业感**: 安全工具UI风格（深色主题、终端风格）

### 1.2 目标用户

- CTF参赛选手（快速了解攻击进度）
- 安全研究员（深度分析攻击过程）
- 平台管理员（监控资源消耗）

---

## 二、页面结构

### 2.1 主布局

```
┌─────────────────────────────────────────────────────────┐
│  Header (Logo + Session Info + Settings)                │
├──────────┬──────────────────────────────────────────────┤
│ Sidebar  │  Main Content Area                           │
│          │                                              │
│ - 任务   │  ┌──────────────────────────────────────┐   │
│ - 探索   │  │  Agent State Overview                │   │
│ - 计划   │  └──────────────────────────────────────┘   │
│ - 攻击   │                                              │
│ - 验证   │  ┌──────────────────────────────────────┐   │
│ - 结果   │  │  Tool Execution Timeline             │   │
│          │  └──────────────────────────────────────┘   │
│ - 设置   │                                              │
│          │  ┌──────────────────────────────────────┐   │
│          │  │  Findings & Flags                    │   │
│          │  └──────────────────────────────────────┘   │
└──────────┴──────────────────────────────────────────────┘
```

### 2.2 页面清单

| 页面 | 路径 | 功能 |
|------|------|------|
| Dashboard | `/` | 任务概览、最近会话、快速启动 |
| Task Create | `/task/new` | 创建新CTF任务、上传附件 |
| Agent Monitor | `/task/:id` | 实时监控Agent执行 |
| Attack Tree | `/task/:id/tree` | 攻击路径可视化 |
| Findings | `/task/:id/findings` | 发现详情、漏洞列表 |
| Reports | `/task/:id/report` | 报告查看、导出 |
| Settings | `/settings` | 配置管理、API密钥设置 |

---

## 三、核心组件

### 3.1 Agent Status Card

显示当前Agent状态：

```tsx
interface AgentStatus {
  agentType: 'explore' | 'plan' | 'attack' | 'verify';
  status: 'idle' | 'running' | 'waiting' | 'error' | 'success';
  currentTask: string;
  progress: number;
  lastUpdate: Date;
  toolsUsed: string[];
}
```

### 3.2 Tool Execution Timeline

实时展示工具调用：

```tsx
interface ToolExecution {
  toolName: string;
  startTime: Date;
  duration: number;
  status: 'pending' | 'running' | 'success' | 'error';
  output: string;
  error?: string;
}
```

### 3.3 Attack Tree Visualization

Mermaid格式攻击树渲染：

```tsx
interface AttackNode {
  id: string;
  label: string;
  status: 'pending' | 'success' | 'failed';
  children: AttackNode[];
}
```

### 3.4 Findings Panel

发现详情展示：

```tsx
interface Finding {
  id: string;
  type: 'endpoint' | 'vuln' | 'credential' | 'flag';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  evidence: string;
  timestamp: Date;
}
```

### 3.5 Token Usage Chart

Token消耗统计图表（Chart.js或Recharts）

### 3.6 Network Topology

网络拓扑图（React Flow或D3.js）

---

## 四、状态管理

### 4.1 全局状态 (Zustand)

```typescript
interface AppState {
  // 当前任务
  currentTask: Task | null;

  // Agent状态
  agents: Record<string, AgentStatus>;

  // 工具执行历史
  toolExecutions: ToolExecution[];

  // 发现列表
  findings: Finding[];

  // Flags
  flags: string[];

  // Token统计
  tokenStats: {
    total: number;
    byModel: Record<string, number>;
    cost: number;
  };

  // WebSocket连接
  wsConnected: boolean;

  // Actions
  updateAgentStatus: (agentType: string, status: AgentStatus) => void;
  addToolExecution: (execution: ToolExecution) => void;
  addFinding: (finding: Finding) => void;
  addFlag: (flag: string) => void;
}
```

### 4.2 WebSocket实时通信

```typescript
// 连接到后端WebSocket
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  switch (data.type) {
    case 'agent_status':
      updateAgentStatus(data.agent, data.status);
      break;

    case 'tool_execution':
      addToolExecution(data.execution);
      break;

    case 'finding':
      addFinding(data.finding);
      break;

    case 'flag':
      addFlag(data.flag);
      break;
  }
};
```

---

## 五、API集成

### 5.1 REST API

```typescript
// 任务管理
POST   /api/tasks              创建任务
GET    /api/tasks/:id          获取任务详情
DELETE /api/tasks/:id          删除任务

// Agent控制
POST   /api/tasks/:id/start    启动Agent
POST   /api/tasks/:id/pause    暂停Agent
POST   /api/tasks/:id/resume   恢复Agent
POST   /api/tasks/:id/stop     停止Agent

// 结果查询
GET    /api/tasks/:id/findings 获取发现列表
GET    /api/tasks/:id/flags    获取Flags
GET    /api/tasks/:id/report   获取报告

// WebSocket
WS     /ws/tasks/:id           实时通信
```

### 5.2 API Client (Axios)

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
});

export const taskApi = {
  create: (data: CreateTaskRequest) =>
    api.post<Task>('/tasks', data),

  get: (id: string) =>
    api.get<Task>(`/tasks/${id}`),

  start: (id: string) =>
    api.post(`/tasks/${id}/start`),
};
```

---

## 六、UI设计系统

### 6.1 颜色主题（深色）

```css
:root {
  --bg-primary: #0d1117;      /* GitHub深色背景 */
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;

  --text-primary: #f0f6fc;
  --text-secondary: #8b949e;

  --accent-blue: #58a6ff;
  --accent-green: #3fb950;
  --accent-orange: #d29922;
  --accent-red: #f85149;

  --border-default: #30363d;
}
```

### 6.2 组件库

使用 **shadcn/ui** (基于Radix UI + Tailwind CSS):

- Button, Input, Select
- Card, Dialog, Sheet
- Tabs, Accordion
- Table, Pagination
- Toast, Badge, Progress

---

## 七、性能优化

### 7.1 虚拟滚动

大量日志输出使用虚拟滚动（react-window）：

```tsx
import { FixedSizeList } from 'react-window';

<FixedSizeList
  height={600}
  itemCount={logs.length}
  itemSize={35}
>
  {({ index, style }) => (
    <div style={style}>{logs[index]}</div>
  )}
</FixedSizeList>
```

### 7.2 状态订阅

使用Zustand selector避免不必要渲染：

```tsx
// 只订阅需要的字段
const agentStatus = useAppStore(
  state => state.agents['attack']
);
```

### 7.3 懒加载

图表和拓扑图懒加载：

```tsx
const AttackTree = lazy(() => import('./AttackTree'));
```

---

## 八、目录结构

```
frontend/
├── src/
│   ├── components/         # 组件
│   │   ├── ui/            # shadcn/ui组件
│   │   ├── AgentStatusCard.tsx
│   │   ├── ToolTimeline.tsx
│   │   ├── AttackTree.tsx
│   │   ├── FindingsPanel.tsx
│   │   └── TokenChart.tsx
│   ├── pages/             # 页面
│   │   ├── Dashboard.tsx
│   │   ├── TaskCreate.tsx
│   │   ├── TaskMonitor.tsx
│   │   └── Settings.tsx
│   ├── store/             # 状态管理
│   │   └── useAppStore.ts
│   ├── api/               # API客户端
│   │   ├── client.ts
│   │   └── types.ts
│   ├── hooks/             # 自定义Hooks
│   │   ├── useWebSocket.ts
│   │   └── useTask.ts
│   ├── lib/               # 工具函数
│   │   └── utils.ts
│   ├── App.tsx
│   └── main.tsx
├── public/
├── index.html
├── tailwind.config.js
├── tsconfig.json
└── package.json
```

---

## 九、开发计划

### Phase 1: 基础框架 (1周)
- [x] 项目初始化（Vite + React + TypeScript）
- [x] Tailwind CSS配置
- [x] shadcn/ui集成
- [x] 路由配置
- [x] 状态管理（Zustand）

### Phase 2: 核心组件 (2周)
- [ ] AgentStatusCard组件
- [ ] ToolTimeline组件
- [ ] FindingsPanel组件
- [ ] TokenChart组件

### Phase 3: 可视化 (1周)
- [ ] AttackTree组件（Mermaid渲染）
- [ ] NetworkTopology组件（React Flow）

### Phase 4: 集成测试 (1周)
- [ ] WebSocket实时通信
- [ ] API集成测试
- [ ] E2E测试（Playwright）

---

## 十、部署

### 10.1 Docker构建

```dockerfile
FROM node:18-alpine as build

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

### 10.2 Nginx配置

```nginx
server {
    listen 80;

    location / {
        root /usr/share/nginx/html;
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://backend:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /ws {
        proxy_pass http://backend:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## 十一、参考资源

- **shadcn/ui**: https://ui.shadcn.com/
- **Tailwind CSS**: https://tailwindcss.com/
- **Zustand**: https://github.com/pmndrs/zustand
- **React Flow**: https://reactflow.dev/
- **Mermaid**: https://mermaid.js.org/

---

**设计完成，准备实现基础框架。**