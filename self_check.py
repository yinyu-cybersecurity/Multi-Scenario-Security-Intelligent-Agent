#!/usr/bin/env python
"""
CTF-Agent Comprehensive Self-Check Script (deploy version)
"""

import sys
import os

# Add app directory to path for deploy structure
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

print('=' * 60)
print('CTF-Agent Comprehensive Self-Check (deploy)')
print('=' * 60)

results = {'pass': 0, 'fail': 0, 'warnings': []}

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
# 6. Graph Structure
# ========================================
print('\n--- Graph Structure ---')
try:
    from ctf_agent_graph import run_single_task, CTFState
    check('graph runner', True)
except Exception as e:
    check('graph runner', False, str(e))

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
# Summary
# ========================================
print('\n' + '=' * 60)
print('SUMMARY')
print('=' * 60)
print(f'Passed: {results["pass"]}')
print(f'Failed: {results["fail"]}')
if results['warnings']:
    print('\nWarnings:')
    for w in results['warnings']:
        print(f'  - {w}')

if results['fail'] == 0:
    print('\n[SUCCESS] All checks passed!')
    sys.exit(0)
else:
    print('\n[ERROR] Some checks failed!')
    sys.exit(1)