# CTF-Agent 交互式聊天界面设计

> **Goal**: 将前端改造为Claude Code风格的交互式聊天界面，支持对话式交互、文件上传、实时监控

> **Design Date**: 2026-04-02

---

## Overview

在现有三栏Dashboard基础上，添加底部输入栏和文件上传功能，实现类似Claude Code CLI的整合式交互体验。用户可以随时输入指令、上传文件、打断AI执行，同时实时查看AI操作日志。

---

## Layout Design

### 整体布局

```
+------------------------------------------------------------------+
|  Header: CTF-Agent 2.0                    [Status] [Settings]     |
+------------------------------------------------------------------+
|  Stats Bar: [Findings] [Flags] [Tools] [Skills] [Iterations]     |
+----------+--------------------------------+----------------------+
|          |                                |                      |
| Timeline |      Log Stream                |   Detail Panel       |
|  (200px) |      (flex-grow)               |      (300px)         |
|          |      实时AI操作日志              |      [可折叠]         |
|          |                                |                      |
|          |      [Think] Analyzing...       |                      |
|          |      [Act] Running nmap...      |                      |
|          |      ━━━━━━━━━━━━ 45%           |                      |
|          |                                |                      |
+----------+--------------------------------+----------------------+
|  AttachmentBar: [file.txt ✕] [image.png ✕]                      |
+------------------------------------------------------------------+
|  ┌──────────────────────────────────────────────────┐  [📎]      |
|  │ 输入指令或描述任务...                              │            |
|  └──────────────────────────────────────────────────┘             |
+------------------------------------------------------------------+
```

### 布局特点

| 区域 | 高度 | 说明 |
|------|------|------|
| Header | 56px | 保持不变 |
| StatsBar | 48px | 保持不变 |
| Timeline | 100% - 240px | 保持不变 |
| LogStream | 100% - 240px | 高度减少约100px |
| DetailPanel | 100% - 240px | 保持不变 |
| AttachmentBar | 32px | 新增，有附件时显示 |
| InputBar | 60-80px | 新增，底部固定 |

---

## Component Design

### 1. InputBar Component

**位置**: 底部固定

**结构**:
```
InputBar (高度约 60-80px)
├── textarea (多行输入，最多3行)
├── 占位符: "输入指令或描述任务..."
├── 支持拖拽文件高亮效果
└── [📎] 文件上传按钮 (左侧)
```

**交互**:
| 快捷键 | 行为 |
|--------|------|
| Enter | 发送消息 |
| Shift+Enter | 换行 |
| Ctrl+C | 打断AI执行 |

**状态**:
- 默认状态: 白色边框
- 拖拽文件: 蓝色高亮边框
- AI执行中: 可输入新指令，Ctrl+C打断

### 2. AttachmentBar Component

**位置**: InputBar上方，有附件时显示

**结构**:
```
AttachmentBar (高度约 32px)
├── 附件列表 (水平滚动, flex布局)
│   ├── [filename.txt ✕]
│   ├── [image.png ✕]
│   └── [archive.zip ✕]
└── 无附件时隐藏
```

**交互**:
- 点击 ✕ 移除单个附件
- 文件名显示，无图标

---

## Message Types

### 日志流消息类型

| 类型 | 前缀 | 颜色 | 示例 |
|------|------|------|------|
| User | `[User]` | 蓝色 | `[User] 分析这个文件` |
| Think | `[Think]` | 琥珀色 | `[Think] 检测到zip压缩包...` |
| Act | `[Act]` | 蓝色 | `[Act] Running nmap...` |
| Reflect | `[Reflect]` | 绿色 | `[Reflect] 发现2个漏洞` |
| File | `[File]` | 灰色 | `[File] 已上传: challenge.zip` |
| System | `[System]` | 灰色 | `[System] 任务中断` |

### 日志流示例

```
[File] 已上传: challenge.zip (15.2MB)
[User] 分析这个文件
[Think] 读取文件内容...
[Think] 检测到zip压缩包，尝试解压...
[Think] 发现内部包含 source.php，判断为Web题目
[Act] 开始分析PHP源码...
│ ━━━━━━━━━━━━ 100% 2.3s
[Reflect] 发现SQL注入点
[User] 尝试SQL注入  (Ctrl+C打断后继续)
[Think] Switching to SQL injection strategy...
```

---

## State Management

### 新增状态类型

```typescript
// frontend/src/store/types.ts

interface Attachment {
  id: string;
  name: string;
  size: number;
  type: string;
  file: File;
}

interface Message {
  id: string;
  role: 'user' | 'system';
  content: string;
  attachments?: Attachment[];
  timestamp: Date;
}

interface ChatState {
  // 输入状态
  inputValue: string;
  attachments: Attachment[];
  isDragging: boolean;
  
  // 执行状态
  isExecuting: boolean;
  currentTask: string;
  
  // 消息历史
  messages: Message[];
}
```

### Store 扩展

```typescript
// useAppStore.ts 新增 actions
interface AppState {
  // ... 现有状态
  
  // Chat 状态
  chat: ChatState;
  
  // Chat Actions
  setInputValue: (value: string) => void;
  addAttachment: (file: Attachment) => void;
  removeAttachment: (id: string) => void;
  clearAttachments: () => void;
  setDragging: (isDragging: boolean) => void;
  setIsExecuting: (isExecuting: boolean) => void;
  addMessage: (message: Message) => void;
  sendUserInput: () => void;
  interruptExecution: () => void;
}
```

---

## WebSocket Communication

### 新增消息类型

```typescript
// 前端发送
| { type: 'user_input'; data: { message: string; attachments: Attachment[] } }
| { type: 'interrupt'; data: { reason: 'user_cancel' } }

// 后端推送
| { type: 'file_uploaded'; data: { fileId: string; filename: string; size: number } }
| { type: 'execution_status'; data: { isExecuting: boolean; task?: string } }
```

### 数据流

```
用户输入 + 附件
    ↓
InputBar 捕获
    ↓
WebSocket 发送 user_input
    ↓
后端接收
    ├── 保存附件到 uploads/{session_id}/
    ├── 返回 file_uploaded 确认
    └── AI开始处理
    ↓
日志流实时推送 (Think/Act/Reflect)
    ↓
用户 Ctrl+C
    ↓
WebSocket 发送 interrupt
    ↓
后端停止当前迭代
```

---

## File Upload

### 前端处理

```typescript
// useFileUpload.ts
interface FileUploadConfig {
  maxFileSize: 50 * 1024 * 1024;  // 50MB
  maxFiles: 5;
  allowedTypes: [];  // 不限制，AI自主判断
}

// 上传流程
1. 用户选择/拖拽文件
2. 前端验证大小和数量
3. 添加到 attachments 状态
4. 显示在 AttachmentBar
5. 发送消息时一并上传
```

### 后端处理

```python
# 文件存储路径
uploads/{session_id}/{file_id}_{filename}

# 不做类型预判，AI自主探索
# AI可通过执行命令获取文件信息:
# - file command
# - unzip -l
# - strings
# - binwalk
# 等
```

### 安全限制

| 限制 | 值 |
|------|-----|
| 单文件最大 | 50MB |
| 单次最多文件 | 5个 |
| 存储位置 | 非web可访问目录 |
| 文件名处理 | UUID + 原始扩展名 |

---

## Component Structure

```
frontend/src/
├── components/
│   ├── Chat/
│   │   ├── InputBar.tsx           # 底部输入框
│   │   ├── AttachmentBar.tsx      # 附件列表
│   │   └── Chat.module.css        # 样式
│   ├── Timeline/                  # 保持不变
│   ├── LogStream/                 # 保持不变
│   ├── DetailPanel/               # 保持不变
│   └── common/                    # 保持不变
├── store/
│   ├── types.ts                   # 扩展类型
│   └── useAppStore.ts             # 扩展状态
├── hooks/
│   ├── useWebSocket.ts            # 扩展消息类型
│   └── useFileUpload.ts           # 新增
└── App.tsx                        # 更新布局
```

---

## Backend API

### WebSocket Endpoints

```
ws://localhost:8000/ws          # 主WebSocket连接
POST /api/upload/{session_id}   # 文件上传
GET /api/files/{session_id}     # 获取文件列表
DELETE /api/files/{file_id}     # 删除文件
```

### 后端消息处理

```python
async def handle_user_input(message: str, attachments: list):
    """处理用户输入"""
    # 1. 保存附件
    for attachment in attachments:
        save_file(attachment)
    
    # 2. 更新AI上下文
    context = build_context(message, attachments)
    
    # 3. 触发AI执行
    await agent.run(context)

async def handle_interrupt():
    """处理打断请求"""
    agent.stop_current_iteration()
    send_log("[System] 用户中断执行")
```

---

## Success Criteria

1. **交互体验**: 用户可随时输入指令，Ctrl+C打断
2. **文件上传**: 支持拖拽、按钮两种方式，最多5个文件
3. **实时监控**: 日志流实时显示AI操作
4. **AI自主性**: 文件类型由AI自主判断，无硬编码
5. **稳定性**: 打断不影响后续执行

---

## Design Checklist

- [x] 布局设计完成
- [x] InputBar组件设计
- [x] AttachmentBar组件设计
- [x] 消息类型定义
- [x] 状态管理设计
- [x] WebSocket消息类型
- [x] 文件上传流程
- [x] 组件文件结构
- [x] 后端API设计