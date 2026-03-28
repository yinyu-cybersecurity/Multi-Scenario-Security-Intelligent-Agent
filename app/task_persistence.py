# app/task_persistence.py
"""
任务持久化模块

功能:
- 任务状态持久化存储
- 任务恢复与继续执行
- 执行历史记录
- 进度追踪

用途:
- 系统重启后恢复任务
- 前端展示任务进度
- 调试与分析
"""
import json
import sqlite3
import time
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path
from contextlib import contextmanager
from logger import get_logger

logger = get_logger("TaskPersistence")


@dataclass
class TaskRecord:
    """任务记录"""
    task_id: str
    target: str
    mode: str  # "web_ctf" or "internal_network"
    status: str  # "pending", "running", "paused", "completed", "failed"
    created_at: float
    updated_at: float
    state_snapshot: Dict = field(default_factory=dict)
    execution_steps: int = 0
    findings: List[Dict] = field(default_factory=list)
    errors: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        result = asdict(self)
        # 添加格式化的时间
        from datetime import datetime
        result["created_at"] = datetime.fromtimestamp(self.created_at).strftime("%Y-%m-%d %H:%M:%S")
        result["updated_at"] = datetime.fromtimestamp(self.updated_at).strftime("%Y-%m-%d %H:%M:%S")
        # 从findings中提取flag信息
        result["found_flag"] = False
        result["final_flag"] = ""
        for finding in self.findings:
            if finding.get("type") == "flag" or "flag" in str(finding.get("content", "")).lower():
                result["found_flag"] = True
                result["final_flag"] = finding.get("content", "")
                break
        # 添加completed_at字段
        if self.status in ["completed", "failed"]:
            result["completed_at"] = result["updated_at"]
        else:
            result["completed_at"] = None
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> 'TaskRecord':
        return cls(**data)


class TaskPersistenceManager:
    """
    任务持久化管理器

    使用 SQLite 存储任务状态，支持:
    - 任务创建、更新、查询
    - 状态快照保存
    - 发现记录
    - 错误追踪
    """

    def __init__(self, db_path: str = None):
        if db_path is None:
            # 默认存储在 data 目录
            data_dir = Path(__file__).parent.parent / "data"
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / "tasks.db")

        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """初始化数据库表"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 任务表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    execution_steps INTEGER DEFAULT 0,
                    state_snapshot TEXT,
                    findings TEXT,
                    errors TEXT,
                    metadata TEXT
                )
            ''')

            # 执行历史表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS execution_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    node TEXT NOT NULL,
                    action TEXT,
                    result TEXT,
                    success INTEGER,
                    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
                )
            ''')

            # 发现记录表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS discoveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    discovery_type TEXT NOT NULL,
                    content TEXT,
                    severity TEXT,
                    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
                )
            ''')

            # 创建索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_history_task ON execution_history(task_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_discoveries_task ON discoveries(task_id)')

            conn.commit()

    @contextmanager
    def _get_connection(self):
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # =========================================================================
    # 任务管理
    # =========================================================================

    def create_task(self, task_id: str, target: str, mode: str, metadata: Dict = None) -> TaskRecord:
        """创建新任务"""
        now = time.time()
        record = TaskRecord(
            task_id=task_id,
            target=target,
            mode=mode,
            status="pending",
            created_at=now,
            updated_at=now,
            metadata=metadata or {}
        )

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO tasks
                    (task_id, target, mode, status, created_at, updated_at, execution_steps, state_snapshot, findings, errors, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record.task_id, record.target, record.mode, record.status,
                    record.created_at, record.updated_at, record.execution_steps,
                    json.dumps(record.state_snapshot, ensure_ascii=False),
                    json.dumps(record.findings, ensure_ascii=False),
                    json.dumps(record.errors, ensure_ascii=False),
                    json.dumps(record.metadata, ensure_ascii=False)
                ))
                conn.commit()

        logger.info(f"创建任务: {task_id} -> {target}")
        return record

    def update_task(self, task_id: str, **updates) -> bool:
        """更新任务状态"""
        now = time.time()

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # 构建更新语句
                set_clauses = ["updated_at = ?"]
                values = [now]

                if "status" in updates:
                    set_clauses.append("status = ?")
                    values.append(updates["status"])

                if "execution_steps" in updates:
                    set_clauses.append("execution_steps = ?")
                    values.append(updates["execution_steps"])

                if "state_snapshot" in updates:
                    set_clauses.append("state_snapshot = ?")
                    values.append(json.dumps(updates["state_snapshot"], ensure_ascii=False))

                if "findings" in updates:
                    set_clauses.append("findings = ?")
                    values.append(json.dumps(updates["findings"], ensure_ascii=False))

                if "errors" in updates:
                    set_clauses.append("errors = ?")
                    values.append(json.dumps(updates["errors"], ensure_ascii=False))

                if "metadata" in updates:
                    set_clauses.append("metadata = ?")
                    values.append(json.dumps(updates["metadata"], ensure_ascii=False))

                values.append(task_id)

                cursor.execute(
                    f"UPDATE tasks SET {', '.join(set_clauses)} WHERE task_id = ?",
                    values
                )
                conn.commit()

                return cursor.rowcount > 0

    def get_task(self, task_id: str) -> Optional[TaskRecord]:
        """获取任务记录"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
            row = cursor.fetchone()

            if row:
                return self._row_to_record(row)
            return None

    def get_tasks_by_status(self, status: str) -> List[TaskRecord]:
        """按状态获取任务"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tasks WHERE status = ? ORDER BY created_at DESC", (status,))
            rows = cursor.fetchall()
            return [self._row_to_record(row) for row in rows]

    def get_active_tasks(self) -> List[TaskRecord]:
        """获取所有活动任务"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM tasks WHERE status IN ('pending', 'running', 'paused') ORDER BY created_at DESC"
            )
            rows = cursor.fetchall()
            return [self._row_to_record(row) for row in rows]

    def get_all_tasks(self, limit: int = 100) -> List[TaskRecord]:
        """获取所有任务（包括已完成的历史任务）"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [self._row_to_record(row) for row in rows]

    def delete_task(self, task_id: str) -> bool:
        """删除任务及其相关记录"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM execution_history WHERE task_id = ?", (task_id,))
                cursor.execute("DELETE FROM discoveries WHERE task_id = ?", (task_id,))
                cursor.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
                conn.commit()
                return cursor.rowcount > 0

    def _row_to_record(self, row: sqlite3.Row) -> TaskRecord:
        """将数据库行转换为 TaskRecord"""
        return TaskRecord(
            task_id=row["task_id"],
            target=row["target"],
            mode=row["mode"],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            execution_steps=row["execution_steps"],
            state_snapshot=json.loads(row["state_snapshot"] or "{}"),
            findings=json.loads(row["findings"] or "[]"),
            errors=json.loads(row["errors"] or "[]"),
            metadata=json.loads(row["metadata"] or "{}")
        )

    # =========================================================================
    # 执行历史
    # =========================================================================

    def record_execution(self, task_id: str, node: str, action: str, result: str, success: bool):
        """记录执行历史"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO execution_history (task_id, timestamp, node, action, result, success)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (task_id, time.time(), node, action, result, 1 if success else 0))
                conn.commit()

    def get_execution_history(self, task_id: str, limit: int = 100) -> List[Dict]:
        """获取执行历史"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM execution_history
                WHERE task_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (task_id, limit))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    # =========================================================================
    # 发现记录
    # =========================================================================

    def record_discovery(self, task_id: str, discovery_type: str, content: str, severity: str = "info"):
        """记录发现"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO discoveries (task_id, timestamp, discovery_type, content, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (task_id, time.time(), discovery_type, content, severity))
                conn.commit()

    def get_discoveries(self, task_id: str) -> List[Dict]:
        """获取所有发现"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM discoveries
                WHERE task_id = ?
                ORDER BY timestamp ASC
            ''', (task_id,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    # =========================================================================
    # 状态快照
    # =========================================================================

    def save_state_snapshot(self, task_id: str, state: Dict):
        """保存状态快照"""
        # 过滤掉不可序列化的字段
        serializable_state = {}
        for key, value in state.items():
            try:
                json.dumps({key: value}, ensure_ascii=False)
                serializable_state[key] = value
            except (TypeError, ValueError):
                serializable_state[key] = str(value)

        self.update_task(task_id, state_snapshot=serializable_state)

    def load_state_snapshot(self, task_id: str) -> Optional[Dict]:
        """加载状态快照"""
        record = self.get_task(task_id)
        if record:
            return record.state_snapshot
        return None

    # =========================================================================
    # 统计信息
    # =========================================================================

    def get_statistics(self) -> Dict:
        """获取任务统计信息"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 总任务数
            cursor.execute("SELECT COUNT(*) FROM tasks")
            total_tasks = cursor.fetchone()[0]

            # 各状态任务数
            cursor.execute("SELECT status, COUNT(*) FROM tasks GROUP BY status")
            status_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # 最近任务
            cursor.execute("SELECT task_id, target, status, created_at FROM tasks ORDER BY created_at DESC LIMIT 5")
            recent_tasks = [dict(row) for row in cursor.fetchall()]

            return {
                "total_tasks": total_tasks,
                "status_counts": status_counts,
                "recent_tasks": recent_tasks
            }


# 全局任务持久化管理器实例
_task_persistence: Optional[TaskPersistenceManager] = None


def get_task_persistence() -> TaskPersistenceManager:
    """获取全局任务持久化管理器"""
    global _task_persistence
    if _task_persistence is None:
        _task_persistence = TaskPersistenceManager()
    return _task_persistence