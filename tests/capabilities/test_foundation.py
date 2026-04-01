"""
FoundationCapability单元测试
"""

import os
import pytest
import tempfile
import asyncio
from pathlib import Path

from app.capabilities.foundation import (
    FoundationCapability,
    FoundationTool,
    FOUNDATION_SCHEMAS,
)


@pytest.fixture
def temp_workspace():
    """创建临时工作目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def foundation(temp_workspace):
    """创建FoundationCapability实例"""
    return FoundationCapability(workspace=temp_workspace)


class TestFoundationToolEnum:
    """测试FoundationTool枚举"""

    def test_enum_values(self):
        """验证枚举值"""
        assert FoundationTool.READ.value == "Read"
        assert FoundationTool.WRITE.value == "Write"
        assert FoundationTool.EDIT.value == "Edit"
        assert FoundationTool.BASH.value == "Bash"
        assert FoundationTool.GLOB.value == "Glob"
        assert FoundationTool.GREP.value == "Grep"


class TestToolSchemas:
    """测试工具Schema"""

    def test_all_tools_have_schemas(self):
        """验证所有工具都有Schema"""
        for tool in FoundationTool:
            assert tool in FOUNDATION_SCHEMAS
            schema = FOUNDATION_SCHEMAS[tool]
            assert schema.name
            assert schema.description
            assert schema.parameters
            assert "properties" in schema.parameters

    def test_schema_api_format(self):
        """验证Schema API格式"""
        schema = FOUNDATION_SCHEMAS[FoundationTool.READ]
        api_format = schema.to_api_format()

        assert "name" in api_format
        assert "description" in api_format
        assert "parameters" in api_format


class TestReadTool:
    """测试Read工具"""

    @pytest.mark.asyncio
    async def test_read_local_file(self, foundation, temp_workspace):
        """测试读取本地文件"""
        # 创建测试文件
        test_file = os.path.join(temp_workspace, "test.txt")
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write("Hello World\nLine 2\nLine 3")

        result = await foundation.execute(
            FoundationTool.READ,
            {"file_path": test_file}
        )

        assert result["success"] == True
        assert "Hello World" in result["data"]["content"]

    @pytest.mark.asyncio
    async def test_read_with_offset_limit(self, foundation, temp_workspace):
        """测试带偏移和限制的读取"""
        # 创建测试文件
        test_file = os.path.join(temp_workspace, "test.txt")
        with open(test_file, 'w', encoding='utf-8') as f:
            for i in range(10):
                f.write(f"Line {i}\n")

        result = await foundation.execute(
            FoundationTool.READ,
            {"file_path": test_file, "offset": 2, "limit": 3}
        )

        assert result["success"] == True
        content = result["data"]["content"]
        assert "Line 2" in content
        assert "Line 4" in content
        assert "Line 5" not in content

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self, foundation):
        """测试读取不存在的文件"""
        result = await foundation.execute(
            FoundationTool.READ,
            {"file_path": "/nonexistent/file.txt"}
        )

        assert result["success"] == False
        assert "不存在" in result["error"]

    @pytest.mark.asyncio
    async def test_read_directory(self, foundation, temp_workspace):
        """测试目录列表"""
        # 创建一些文件
        os.makedirs(os.path.join(temp_workspace, "subdir"))
        Path(os.path.join(temp_workspace, "file1.txt")).touch()
        Path(os.path.join(temp_workspace, "file2.py")).touch()

        result = await foundation.execute(
            FoundationTool.READ,
            {"file_path": temp_workspace}
        )

        assert result["success"] == True
        entries = result["data"]["entries"]
        assert len(entries) == 3  # file1.txt, file2.py, subdir


class TestWriteTool:
    """测试Write工具"""

    @pytest.mark.asyncio
    async def test_write_new_file(self, foundation, temp_workspace):
        """测试写入新文件"""
        result = await foundation.execute(
            FoundationTool.WRITE,
            {
                "file_path": "new_file.txt",
                "content": "Test content"
            }
        )

        assert result["success"] == True
        assert os.path.exists(os.path.join(temp_workspace, "new_file.txt"))

    @pytest.mark.asyncio
    async def test_write_creates_directories(self, foundation, temp_workspace):
        """测试自动创建目录"""
        result = await foundation.execute(
            FoundationTool.WRITE,
            {
                "file_path": "sub/dir/file.txt",
                "content": "Test"
            }
        )

        assert result["success"] == True
        assert os.path.exists(os.path.join(temp_workspace, "sub/dir/file.txt"))

    @pytest.mark.asyncio
    async def test_write_overwrites_existing(self, foundation, temp_workspace):
        """测试覆盖现有文件"""
        file_path = os.path.join(temp_workspace, "test.txt")

        # 第一次写入
        await foundation.execute(
            FoundationTool.WRITE,
            {"file_path": file_path, "content": "Original"}
        )

        # 第二次写入
        result = await foundation.execute(
            FoundationTool.WRITE,
            {"file_path": file_path, "content": "Overwritten"}
        )

        assert result["success"] == True
        with open(file_path, 'r', encoding='utf-8') as f:
            assert f.read() == "Overwritten"


class TestEditTool:
    """测试Edit工具"""

    @pytest.mark.asyncio
    async def test_edit_replace_string(self, foundation, temp_workspace):
        """测试字符串替换"""
        file_path = os.path.join(temp_workspace, "test.txt")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("Hello World")

        result = await foundation.execute(
            FoundationTool.EDIT,
            {
                "file_path": file_path,
                "old_string": "World",
                "new_string": "CTF"
            }
        )

        assert result["success"] == True
        with open(file_path, 'r', encoding='utf-8') as f:
            assert f.read() == "Hello CTF"

    @pytest.mark.asyncio
    async def test_edit_string_not_found(self, foundation, temp_workspace):
        """测试字符串不存在"""
        file_path = os.path.join(temp_workspace, "test.txt")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("Hello World")

        result = await foundation.execute(
            FoundationTool.EDIT,
            {
                "file_path": file_path,
                "old_string": "NotFound",
                "new_string": "Replace"
            }
        )

        assert result["success"] == False
        assert "未找到" in result["error"]

    @pytest.mark.asyncio
    async def test_edit_ambiguous_match(self, foundation, temp_workspace):
        """测试模糊匹配（多个匹配）"""
        file_path = os.path.join(temp_workspace, "test.txt")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("line line line")

        result = await foundation.execute(
            FoundationTool.EDIT,
            {
                "file_path": file_path,
                "old_string": "line",
                "new_string": "word"
            }
        )

        assert result["success"] == False
        assert "不唯一" in result["error"]


class TestBashTool:
    """测试Bash工具"""

    @pytest.mark.asyncio
    async def test_bash_simple_command(self, foundation):
        """测试简单命令"""
        result = await foundation.execute(
            FoundationTool.BASH,
            {"command": "echo Hello"}
        )

        assert result["success"] == True
        assert "Hello" in result["data"]["stdout"]

    @pytest.mark.asyncio
    async def test_bash_command_failure(self, foundation):
        """测试命令失败"""
        result = await foundation.execute(
            FoundationTool.BASH,
            {"command": "exit 1"}
        )

        assert result["success"] == False
        assert result["data"]["returncode"] == 1

    @pytest.mark.asyncio
    async def test_bash_timeout(self, foundation):
        """测试超时"""
        result = await foundation.execute(
            FoundationTool.BASH,
            {"command": "sleep 10", "timeout": 100}  # 100ms超时
        )

        assert result["success"] == False
        assert "超时" in result["error"]

    @pytest.mark.asyncio
    async def test_bash_background(self, foundation):
        """测试后台执行"""
        result = await foundation.execute(
            FoundationTool.BASH,
            {"command": "sleep 1", "background": True}
        )

        assert result["success"] == True
        assert result["data"]["background"] == True
        assert "pid" in result["data"]

    @pytest.mark.asyncio
    async def test_bash_dangerous_command_blocked(self, foundation):
        """测试危险命令被阻止"""
        result = await foundation.execute(
            FoundationTool.BASH,
            {"command": "rm -rf /*"}
        )

        assert result["success"] == False
        assert "阻止" in result["error"]


class TestGlobTool:
    """测试Glob工具"""

    @pytest.mark.asyncio
    async def test_glob_find_files(self, foundation, temp_workspace):
        """测试查找文件"""
        # 创建测试文件
        Path(os.path.join(temp_workspace, "test.py")).touch()
        Path(os.path.join(temp_workspace, "test.txt")).touch()
        Path(os.path.join(temp_workspace, "readme.md")).touch()

        result = await foundation.execute(
            FoundationTool.GLOB,
            {"pattern": "*.py"}
        )

        assert result["success"] == True
        assert len(result["data"]["files"]) == 1
        assert "test.py" in result["data"]["files"][0]

    @pytest.mark.asyncio
    async def test_glob_recursive(self, foundation, temp_workspace):
        """测试递归搜索"""
        # 创建嵌套目录
        os.makedirs(os.path.join(temp_workspace, "sub"))
        Path(os.path.join(temp_workspace, "sub", "nested.py")).touch()
        Path(os.path.join(temp_workspace, "root.py")).touch()

        result = await foundation.execute(
            FoundationTool.GLOB,
            {"pattern": "**/*.py"}
        )

        assert result["success"] == True
        assert result["data"]["count"] == 2


class TestGrepTool:
    """测试Grep工具"""

    @pytest.mark.asyncio
    async def test_grep_find_pattern(self, foundation, temp_workspace):
        """测试查找模式"""
        # 创建测试文件
        file_path = os.path.join(temp_workspace, "test.txt")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("Hello World\nLine with password=secret\nAnother line")

        result = await foundation.execute(
            FoundationTool.GREP,
            {"pattern": "password"}
        )

        assert result["success"] == True
        assert result["data"]["count"] == 1
        assert "password" in result["data"]["matches"][0]["content"]

    @pytest.mark.asyncio
    async def test_grep_with_glob(self, foundation, temp_workspace):
        """测试带文件过滤的搜索"""
        # 创建多个文件
        with open(os.path.join(temp_workspace, "test.py"), 'w', encoding='utf-8') as f:
            f.write("API_KEY = 'secret'\n")
        with open(os.path.join(temp_workspace, "test.txt"), 'w', encoding='utf-8') as f:
            f.write("API_KEY = 'another'\n")

        result = await foundation.execute(
            FoundationTool.GREP,
            {"pattern": "API_KEY", "glob": "*.py"}
        )

        assert result["success"] == True
        assert result["data"]["count"] == 1
        assert "test.py" in result["data"]["matches"][0]["file"]

    @pytest.mark.asyncio
    async def test_grep_regex(self, foundation, temp_workspace):
        """测试正则表达式"""
        file_path = os.path.join(temp_workspace, "test.txt")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("user@example.com\nnot an email\nadmin@test.org")

        result = await foundation.execute(
            FoundationTool.GREP,
            {"pattern": r"[\w.-]+@[\w.-]+\.\w+"}
        )

        assert result["success"] == True
        assert result["data"]["count"] == 2