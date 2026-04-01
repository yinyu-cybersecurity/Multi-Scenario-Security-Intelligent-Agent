#!/usr/bin/env python
"""
CTF-Agent 综合自检脚本 (deploy版本)

增强功能:
- 工具可用性检查
- 网络连接测试
- 配置验证
- LLM 连接测试
- 持久化模块测试
"""

import sys
import os
import json
import shutil
import subprocess
import socket
from pathlib import Path

# Add app directory to path for deploy structure
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

print('=' * 60)
print('CTF-Agent Comprehensive Self-Check (deploy)')
print('=' * 60)

results = {'pass': 0, 'fail': 0, 'warnings': [], 'skipped': 0}

def check(name, condition, detail=''):
    global results
    if condition:
        print(f'[OK] {name}')
        results['pass'] += 1
    else:
        print(f'[FAIL] {name}')
        results['fail'] += 1
        if detail:
            results['warnings'].append(f'{name}: {detail}')

def skip(name, reason=''):
    global results
    print(f'[SKIP] {name}' + (f' - {reason}' if reason else ''))
    results['skipped'] += 1

def warn(name, detail):
    global results
    print(f'[WARN] {name}: {detail}')
    results['warnings'].append(f'{name}: {detail}')

# ========================================
# 1. Core Module Imports
# ========================================
print('\n--- Core Module Imports ---')
try:
    from state import CTFState, cap_list_reducer
    check('state module', True)
except Exception as e:
    check('state module', False, str(e))

try:
    from router import (
        route_mode, route_verify,
        route_evolution,
        route_internal_mode, route_internal_to_web
    )
    check('router module', True)
except Exception as e:
    check('router module', False, str(e))

try:
    from tool_framework import ToolRegistry, CTFTool, CommandLineTool
    check('tool_framework module', True)
except Exception as e:
    check('tool_framework module', False, str(e))

try:
    from llm_client import llm_client, LLMResult
    check('llm_client module', True)
except Exception as e:
    check('llm_client module', False, str(e))

try:
    from self_correction import SelfCorrectionManager
    check('self_correction module', True)
except Exception as e:
    check('self_correction module', False, str(e))

try:
    from logger import get_logger, set_task, node_log
    check('logger module', True)
except Exception as e:
    check('logger module', False, str(e))

try:
    from performance import PerformanceMonitor, performance_monitor
    check('performance module', True)
except Exception as e:
    check('performance module', False, str(e))

try:
    from topology.builder import TopologyBuilder
    check('topology.builder module', True)
except Exception as e:
    check('topology.builder module', False, str(e))

try:
    from topology.analyzer import TopologyAnalyzer
    check('topology.analyzer module', True)
except Exception as e:
    check('topology.analyzer module', False, str(e))

# ========================================
# 2. New Tool Imports
# ========================================
print('\n--- New Tool Imports ---')
try:
    from tools.db_attacks import DatabaseAttacker
    check('db_attacks module', True)
except Exception as e:
    check('db_attacks module', False, str(e))

try:
    from tools.nuclei_scanner import NucleiScanner
    check('nuclei_scanner module', True)
except Exception as e:
    check('nuclei_scanner module', False, str(e))

try:
    from tools.frp_manager import FRPManager
    check('frp_manager module', True)
except Exception as e:
    check('frp_manager module', False, str(e))

try:
    from tools.payload_mutator import PayloadMutator
    check('payload_mutator module', True)
except Exception as e:
    check('payload_mutator module', False, str(e))

try:
    from tools.cloud_scanner import CloudScanner
    check('cloud_scanner module', True)
except Exception as e:
    check('cloud_scanner module', False, str(e))

try:
    from tools.ssrf_scanner import SSRFScanner
    check('ssrf_scanner module', True)
except Exception as e:
    check('ssrf_scanner module', False, str(e))

try:
    from tools.ai_attacker import AIAttacker
    check('ai_attacker module', True)
except Exception as e:
    check('ai_attacker module', False, str(e))

try:
    from tools.oa_exploiter import OAExploiter
    check('oa_exploiter module', True)
except Exception as e:
    check('oa_exploiter module', False, str(e))

# ========================================
# 3. Internal Network Module Imports
# ========================================
print('\n--- Internal Network Module ---')
try:
    from internal_network.nodes import (
        internal_recon_node, lateral_move_node,
        privilege_escalation_node, credential_gather_node
    )
    check('internal_network.nodes', True)
except Exception as e:
    check('internal_network.nodes', False, str(e))

try:
    from internal_network.kerberos_attacks import KerberosAttacker
    check('kerberos_attacks module', True)
except Exception as e:
    check('kerberos_attacks module', False, str(e))

try:
    from internal_network.credential_manager import CredentialManager, CredentialType, PrivilegeLevel
    check('credential_manager module', True)
except Exception as e:
    check('credential_manager module', False, str(e))

try:
    from internal_network.advanced_operations import (
        OperationStatus, OperationResult, PrivilegeEscalation,
        RemoteDesktopHandler, FileTransferHandler, CredentialDumper
    )
    check('advanced_operations module', True)
except Exception as e:
    check('advanced_operations module', False, str(e))

try:
    from internal_network.post_exploit import post_exploit_node
    check('post_exploit module', True)
except Exception as e:
    check('post_exploit module', False, str(e))

# ========================================
# 4. Remote Executor Module
# ========================================
print('\n--- Remote Executor Module ---')
try:
    from remote_executor import (
        ShellSessionManager, ShellSession, ShellType,
        WebShellExecutor, SSHExecutor, ImpacketExecutor, ProxyExecutor,
        FileTransfer, TunnelManager, TunnelConfig, TunnelStatus
    )
    check('remote_executor core', True)
except Exception as e:
    check('remote_executor core', False, str(e))

try:
    from remote_executor import (
        start_local_frps, check_frps_status,
        start_http_server, check_tools_directory
    )
    check('remote_executor utilities', True)
except Exception as e:
    check('remote_executor utilities', False, str(e))

try:
    from remote_executor.executors import execute_on_session, ExecutionResult
    check('remote_executor.executors', True)
except Exception as e:
    check('remote_executor.executors', False, str(e))

# ========================================
# 5. Memory Module
# ========================================
print('\n--- Memory Module ---')
try:
    from memory.memory_manager import MemoryManager, get_memory_manager
    check('memory_manager module', True)
except Exception as e:
    check('memory_manager module', False, str(e))

# ========================================
# 6. Graph Structure (New Architecture)
# ========================================
print('\n--- Graph Structure (New Architecture) ---')
try:
    from agents.autonomous_agent import AutonomousAgent, AgentState
    check('autonomous_agent module', True)
except Exception as e:
    check('autonomous_agent module', False, str(e))

try:
    from agents.base import AgentType
    check('agents.base module', True)
except Exception as e:
    check('agents.base module', False, str(e))

try:
    from tools_v2.tools import list_tools, execute_tool
    check('tools_v2 module', True)
except Exception as e:
    check('tools_v2 module', False, str(e))

try:
    from coordinator.dispatcher import AgentDispatcher, TaskType
    check('coordinator.dispatcher module', True)
except Exception as e:
    check('coordinator.dispatcher module', False, str(e))

# Legacy import for backward compatibility
try:
    from ctf_agent_graph import run_single_task, CTFState
    check('legacy graph runner', True)
except Exception as e:
    skip('legacy graph runner', 'old architecture - use autonomous_agent')

# ========================================
# 7. Functionality Tests
# ========================================
print('\n--- Functionality Tests ---')

# Test PayloadMutator
try:
    mutator = PayloadMutator
    variants = mutator.generate_sql_variants("' OR '1'='1")
    check('PayloadMutator SQL variants', len(variants) > 0)
except Exception as e:
    check('PayloadMutator SQL variants', False, str(e))

try:
    variants = mutator.generate_cmd_variants('whoami')
    check('PayloadMutator CMD variants', len(variants) > 0)
except Exception as e:
    check('PayloadMutator CMD variants', False, str(e))

try:
    variants = mutator.generate_xss_variants('<script>alert(1)</script>')
    check('PayloadMutator XSS variants', len(variants) > 0)
except Exception as e:
    check('PayloadMutator XSS variants', False, str(e))

# Test CredentialManager
try:
    cm = CredentialManager(storage_file='.memory/test_creds.json')
    cm.add_plaintext('192.168.1.1', 'admin', 'password123')
    creds = cm.get_all()
    check('CredentialManager add/get', len(creds) > 0)
    # Cleanup
    cm.clear()
except Exception as e:
    check('CredentialManager add/get', False, str(e))

# Test MemoryManager
try:
    mm = MemoryManager(memory_dir='.memory_test')
    mm.save_known_fact('test_type', 'test content', 'self-check')
    facts = mm.get_known_facts()
    check('MemoryManager save/get', 'test content' in facts)
except Exception as e:
    check('MemoryManager save/get', False, str(e))

# ========================================
# 8. State Structure
# ========================================
print('\n--- State Structure ---')
try:
    # Check required fields exist
    from state import CTFState
    import inspect
    # CTFState is a TypedDict, check its annotations
    annotations = CTFState.__annotations__
    required_fields = [
        'target_url', 'visited_urls', 'vuln_candidates',
        'credentials', 'attack_results', 'current_round',
        'current_mode', 'execution_steps', 'failure_weighted_score'
    ]
    missing = [f for f in required_fields if f not in annotations]
    check('State required fields', len(missing) == 0, f'Missing: {missing}')
except Exception as e:
    check('State required fields', False, str(e))

# ========================================
# 9. Tool Registration
# ========================================
print('\n--- Tool Registration ---')
try:
    from tools.db_attacks import register as reg_db
    from tools.nuclei_scanner import register as reg_nuclei
    from tools.frp_manager import register as reg_frp
    from tools.cloud_scanner import register as reg_cloud
    check('Tool register functions', True)
except Exception as e:
    check('Tool register functions', False, str(e))

# ========================================
# 10. Tool Availability
# ========================================
print('\n--- Tool Availability ---')

tool_commands = {
    'nmap': ['nmap', '--version'],
    'sqlmap': ['sqlmap', '--version'],
    'gobuster': ['gobuster', 'version'],
    'hydra': ['hydra', '-h'],
    'nuclei': ['nuclei', '-version'],
    'ffuf': ['ffuf', '-V'],
    'curl': ['curl', '--version'],
    'wget': ['wget', '--version'],
    'crackmapexec': ['crackmapexec', '--version'],
    'cme': ['cme', '--version'],  # crackmapexec alias
}

for tool_name, cmd in tool_commands.items():
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        if result.returncode == 0 or tool_name in result.stderr.decode('utf-8', errors='ignore').lower():
            check(f'{tool_name} available', True)
        else:
            warn(f'{tool_name}', 'installed but may need configuration')
            check(f'{tool_name} available', True)
    except FileNotFoundError:
        skip(f'{tool_name} available', 'not installed')
    except subprocess.TimeoutExpired:
        warn(f'{tool_name}', 'timeout during check')
        check(f'{tool_name} available', True)  # May still work
    except Exception as e:
        check(f'{tool_name} available', False, str(e))

# fscan special check
try:
    result = subprocess.run(['fscan'], capture_output=True, timeout=5)
    output = result.stdout.decode('utf-8', errors='ignore') + result.stderr.decode('utf-8', errors='ignore')
    if 'fscan' in output.lower() or result.returncode in [0, 1]:
        check('fscan available', True)
    else:
        skip('fscan available', 'not in PATH')
except FileNotFoundError:
    skip('fscan available', 'not installed')
except Exception as e:
    skip('fscan available', str(e))

# ========================================
# 11. Configuration Validation
# ========================================
print('\n--- Configuration Validation ---')

try:
    from config import config

    # Check API key
    if config.LLM_API_KEY and len(config.LLM_API_KEY) > 10:
        check('LLM API key configured', True)
    else:
        check('LLM API key configured', False, 'API key missing or too short')

    # Check base URL
    if config.LLM_BASE_URL:
        check('LLM base URL configured', True)
    else:
        check('LLM base URL configured', False, 'base URL missing')

    # Check timeout settings
    if config.NODE_TIMEOUT > 0:
        check('NODE_TIMEOUT set', True, f'{config.NODE_TIMEOUT}s')
    else:
        check('NODE_TIMEOUT set', False, 'must be positive')

    # Check public IP
    if config.LOCAL_PUBLIC_IP:
        check('LOCAL_PUBLIC_IP configured', True, config.LOCAL_PUBLIC_IP)
    else:
        warn('LOCAL_PUBLIC_IP', 'not set, tunnel features may not work')
        check('LOCAL_PUBLIC_IP configured', True)

except Exception as e:
    check('Configuration validation', False, str(e))

# ========================================
# 12. Network Connectivity
# ========================================
print('\n--- Network Connectivity ---')

# DNS resolution test
try:
    socket.gethostbyname('www.baidu.com')
    check('DNS resolution', True)
except Exception as e:
    check('DNS resolution', False, str(e))

# HTTP test
try:
    import requests
    requests.get('https://www.baidu.com', timeout=5)
    check('HTTP connectivity', True)
except Exception as e:
    check('HTTP connectivity', False, str(e))

# Local ports check
required_ports = [8000, 7000, 10800]  # HTTP server, frps, SOCKS5
for port in required_ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    if result == 0:
        print(f'[INFO] Port {port} is in use')
    else:
        print(f'[INFO] Port {port} is available')

# ========================================
# 13. LLM Connection Test
# ========================================
print('\n--- LLM Connection Test ---')

try:
    from llm_client import llm_client, LLMErrorType

    # Simple test call
    result = llm_client.call_with_details(
        model='gpt-4o-mini',  # Use cheaper model for test
        messages=[{'role': 'user', 'content': 'Reply with: OK'}],
        max_tokens=10,
        retry_count=1
    )

    if result.success:
        check('LLM connection', True)
        print(f'       Response: {result.content[:50]}...' if len(result.content) > 50 else f'       Response: {result.content}')
    else:
        check('LLM connection', False, f'{result.error_type.value}: {result.error_message}')
except Exception as e:
    check('LLM connection', False, str(e))

# ========================================
# 14. Persistence Test
# ========================================
print('\n--- Persistence Module Test ---')

try:
    from task_persistence import TaskPersistenceManager

    # Use temp database for test
    test_db = Path(__file__).parent / 'data' / 'test_tasks.db'
    test_db.parent.mkdir(exist_ok=True)

    pm = TaskPersistenceManager(db_path=str(test_db))

    # Test create task
    record = pm.create_task('test_001', 'http://test.local', 'web_ctf')
    check('TaskPersistence create', record.task_id == 'test_001')

    # Test get task
    retrieved = pm.get_task('test_001')
    check('TaskPersistence get', retrieved is not None)

    # Test update task
    pm.update_task('test_001', status='running', execution_steps=5)
    updated = pm.get_task('test_001')
    check('TaskPersistence update', updated.status == 'running' and updated.execution_steps == 5)

    # Test record execution
    pm.record_execution('test_001', 'test_node', 'test_action', 'test_result', True)
    history = pm.get_execution_history('test_001')
    check('TaskPersistence history', len(history) > 0)

    # Test statistics
    stats = pm.get_statistics()
    check('TaskPersistence stats', 'total_tasks' in stats)

    # Cleanup
    pm.delete_task('test_001')
    if test_db.exists():
        test_db.unlink()

except Exception as e:
    check('Persistence module', False, str(e))

# ========================================
# 15. Self-Correction Test
# ========================================
print('\n--- Self-Correction Module Test ---')

try:
    from self_correction import SelfCorrectionManager, ErrorSeverity

    scm = SelfCorrectionManager()

    # Test error recording
    record = scm.record_error(
        node='test_node',
        error_type='TEST_ERROR',
        error_message='Test error message',
        severity=ErrorSeverity.LOW
    )
    check('SelfCorrection record', record.error_type == 'TEST_ERROR')

    # Test health check
    from state import CTFState
    test_state = {'target_url': 'http://test.local', 'execution_steps': 1}
    health = scm.check_health(test_state)
    check('SelfCorrection health check', health is not None)

    # Test recovery stats
    stats = scm.get_recovery_stats()
    check('SelfCorrection stats', 'total_errors' in stats)

except Exception as e:
    check('Self-correction module', False, str(e))

# ========================================
# 16. Context Compression Test
# ========================================
print('\n--- Context Compression Test ---')

try:
    from context_compressor import ContextCompressor

    compressor = ContextCompressor()

    # Test token estimation
    test_text = "This is a test string for token estimation."
    tokens = compressor.estimate_tokens(test_text)
    check('ContextCompressor estimate_tokens', tokens > 0)

    # Test should_compress
    small_state = {'test': 'small'}
    large_state = {'test': 'x' * 100000}  # Large string

    check('ContextCompressor should_compress (small)', not compressor.should_compress(small_state))
    check('ContextCompressor should_compress (large)', compressor.should_compress(large_state))

    # Test compression stats
    stats = compressor.get_compression_stats()
    check('ContextCompressor stats', 'total_compressions' in stats)

except Exception as e:
    check('Context compression module', False, str(e))

# ========================================
# Summary
# ========================================
print('\n' + '=' * 60)
print('SUMMARY')
print('=' * 60)
print(f'Passed: {results["pass"]}')
print(f'Failed: {results["fail"]}')
print(f'Skipped: {results["skipped"]}')
if results['warnings']:
    print('\nWarnings:')
    for w in results['warnings']:
        print(f'  - {w}')

if results['fail'] == 0:
    print('\n[SUCCESS] All critical checks passed!')
    sys.exit(0)
else:
    print('\n[ERROR] Some checks failed!')
    sys.exit(1)