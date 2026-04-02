#!/usr/bin/env python3
"""
Agentic Security Analyzer - 智能安全分析器
不是纯脚本，而是有理解能力的 agent

核心思维：
1. 观察现象 -> 2. 理解原因 -> 3. 推断本质 -> 4. 调整策略
"""

import re
import json
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import requests


class UnderstandingLevel(Enum):
    """理解层级"""
    SURFACE = "surface"      # 表面现象 (纯脚本级别)
    CONTEXT = "context"      # 上下文理解 (agent 级别)
    CAUSAL = "causal"       # 因果推理 (高级 agent)
    STRATEGIC = "strategic"  # 战略调整 (专家级别)


@dataclass
class Finding:
    """发现"""
    what: str           # 观察到什么
    so_what: str        # 这意味着什么 (关键！)
    why: str            # 为什么
    implication: str     # 对测试的影响
    strategy: str       # 调整后的策略
    confidence: float  # 置信度 0-1


@dataclass
class AnalysisResult:
    """分析结果"""
    target: str
    understanding_level: UnderstandingLevel
    
    # 现象
    observations: List[str] = field(default_factory=list)
    
    # 发现
    findings: List[Finding] = field(default_factory=list)
    
    # 推断
    inferences: List[str] = field(default_factory=list)
    
    # 最终结论
    conclusion: str = ""
    
    # 调整后的策略
    adjusted_strategy: List[str] = field(default_factory=list)
    
    # 可测试的端点
    testable_endpoints: List[Dict] = field(default_factory=list)
    
    # 不可达的端点 (内网/外网)
    unreachable_endpoints: List[Dict] = field(default_factory=list)


class AgenticAnalyzer:
    """
    智能分析器
    
    不是简单地给响应打标签，而是：
    1. 观察多个现象
    2. 寻找规律
    3. 推断原因
    4. 调整策略
    """
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.observations: List[Dict] = []
        self.patterns: Dict[str, int] = {}
    
    def observe(self, url: str, response: requests.Response) -> Dict:
        """观察响应"""
        obs = {
            'url': url,
            'status': response.status_code,
            'content_type': response.headers.get('Content-Type', ''),
            'length': len(response.content),
            'is_html': '<!doctype' in response.text.lower() or '<html' in response.text.lower(),
            'is_json': self._is_json(response.text),
            'content_preview': response.text[:200],
        }
        
        # 检测 SPA 特征
        obs['spa_indicators'] = self._detect_spa_indicators(response.text)
        
        # 检测 API 特征
        obs['api_indicators'] = self._detect_api_indicators(response.text)
        
        self.observations.append(obs)
        
        # 记录模式
        if obs['is_html'] and obs['length'] == 678:  # 固定的 SPA fallback 大小
            key = f"spa_fallback_{obs['length']}"
            self.patterns[key] = self.patterns.get(key, 0) + 1
        
        return obs
    
    def _is_json(self, content: str) -> bool:
        try:
            json.loads(content)
            return True
        except:
            return False
    
    def _detect_spa_indicators(self, content: str) -> List[str]:
        indicators = []
        content_lower = content.lower()
        
        if 'chunk-vendors' in content_lower:
            indicators.append('webpack_chunk_vendors')
        if '<div id="app">' in content_lower:
            indicators.append('div_id_app')
        if '<div id="root">' in content_lower:
            indicators.append('div_id_root')
        if '<noscript>' in content_lower:
            indicators.append('noscript_tag')
        if 'vue' in content_lower:
            indicators.append('vue_keyword')
        if 'react' in content_lower:
            indicators.append('react_keyword')
        
        return indicators
    
    def _detect_api_indicators(self, content: str) -> List[str]:
        indicators = []
        content_lower = content.lower()
        
        if '"swagger"' in content_lower or "'swagger'" in content_lower:
            indicators.append('swagger_keyword')
        if '"openapi"' in content_lower or "'openapi'" in content_lower:
            indicators.append('openapi_keyword')
        if '"paths"' in content_lower:
            indicators.append('paths_keyword')
        if '/api/' in content_lower:
            indicators.append('api_path')
        if '__schema' in content_lower:
            indicators.append('graphql_schema')
        
        return indicators
    
    def reason(self) -> AnalysisResult:
        """
        推理分析
        
        从观察到推断：
        1. 所有路径返回相同大小的 HTML？
        2. 有 SPA 特征但请求的是 JSON 文件？
        3. 从 JS 中发现的后端地址是什么？
        """
        result = AnalysisResult(
            target="current_target",
            understanding_level=UnderstandingLevel.SURFACE
        )
        
        # 收集观察
        result.observations = [o['url'] for o in self.observations]
        
        # === 因果推理 ===
        
        # 检查模式 1: 所有路径都返回相同大小的 HTML
        html_observations = [o for o in self.observations if o.get('is_html')]
        if len(html_observations) >= 3:
            lengths = set(o['length'] for o in html_observations)
            if len(lengths) == 1:
                length = list(lengths)[0]
                
                finding = Finding(
                    what=f"所有 {len(html_observations)} 个不同路径都返回完全相同大小的 HTML ({length} 字节)",
                    so_what="这是典型的 SPA (Vue.js/React) fallback 行为",
                    why="前端服务器(Nginx)配置了 catch-all 路由，将所有请求都路由到 index.html",
                    implication="后端 API 不在当前服务器，可能在内网 (如 118.31.34.105:8081) 或其他地址",
                    strategy="1. 从 JS 中提取后端 API 地址 2. 尝试不同端口/路径探测 3. 如内网地址需要代理访问",
                    confidence=0.95
                )
                result.findings.append(finding)
                result.understanding_level = UnderstandingLevel.CAUSAL
        
        # 检查模式 2: 请求 JSON 文件但返回 HTML
        json_requests = []
        for o in self.observations:
            if '.json' in o['url'] or 'swagger' in o['url'] or 'api-docs' in o['url']:
                if not o.get('is_json'):
                    json_requests.append(o)
        
        if len(json_requests) >= 2:
            finding = Finding(
                what=f"请求了 {len(json_requests)} 个 JSON/YAML 文件，但全部返回 HTML",
                so_what="这些路径在服务端不存在，是前端在模拟",
                why="后端 API 服务器与前端分离，SPA fallback 导致请求被发到前端",
                implication="无法通过前端服务器访问真正的 API 文档和服务",
                strategy="1. 识别后端真实地址（从 JS 或网络请求中）2. 直接测试后端地址 3. 使用代理工具（如 Burp）监控真实请求",
                confidence=0.9
            )
            result.findings.append(finding)
        
        # 检查模式 3: 从 JS 分析后端地址
        js_api_patterns = []
        for o in self.observations:
            if o.get('api_indicators'):
                # 从 JS 内容中检测到 API 相关内容
                pass
        
        # === 生成结论 ===
        if result.findings:
            result.conclusion = self._generate_conclusion(result.findings)
            result.understanding_level = UnderstandingLevel.CAUSAL
            
            # 调整策略
            for finding in result.findings:
                result.adjusted_strategy.append(finding.strategy)
        
        return result
    
    def _generate_conclusion(self, findings: List[Finding]) -> str:
        """生成综合结论"""
        if not findings:
            return "未发现明显问题"
        
        conclusions = []
        
        for f in findings:
            if f.confidence >= 0.9:
                conclusions.append(f"[高置信度] {f.so_what}")
        
        if not conclusions:
            for f in findings:
                conclusions.append(f"[中置信度] {f.so_what}")
        
        return "; ".join(conclusions)
    
    def from_js_analysis(self, js_findings: Dict) -> AnalysisResult:
        """
        从 JS 分析结果进行推理
        
        Args:
            js_findings: {
                'base_urls': [...],
                'api_paths': [...],
                'sensitive_data': [...],
                'backend_indicators': [...]
            }
        """
        result = AnalysisResult(
            target="discovered_from_js",
            understanding_level=UnderstandingLevel.CONTEXT
        )
        
        base_urls = js_findings.get('base_urls', [])
        api_paths = js_findings.get('api_paths', [])
        
        # 检查是否发现内网地址
        internal_ips = []
        for url in base_urls:
            if self._is_internal_ip(url):
                internal_ips.append(url)
        
        if internal_ips:
            finding = Finding(
                what=f"从 JS 中发现 {len(internal_ips)} 个后端地址: {internal_ips}",
                so_what="后端 API 在内网环境，前端无法直接访问",
                why="系统采用前后端分离架构，后端部署在内网",
                implication="无法从外部直接测试后端 API，需要通过代理或内网访问",
                strategy="1. 标记内网地址 2. 建议通过代理工具访问 3. 或寻找外网暴露的测试环境",
                confidence=0.95
            )
            result.findings.append(finding)
            result.unreachable_endpoints = [{'url': ip, 'reason': '内网地址'} for ip in internal_ips]
        
        # 检查是否发现外部可访问地址
        external_apis = []
        for url in base_urls:
            if not self._is_internal_ip(url):
                external_apis.append(url)
        
        if external_apis:
            result.testable_endpoints = [{'url': url, 'accessible': True} for url in external_apis]
        
        if result.findings:
            result.conclusion = self._generate_conclusion(result.findings)
            result.adjusted_strategy = [f.strategy for f in result.findings]
        
        return result
    
    def _is_internal_ip(self, url: str) -> bool:
        """判断是否为内网地址"""
        internal_patterns = [
            r'10\.\d+\.\d+\.\d+',
            r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',
            r'192\.168\.\d+\.\d+',
            r'127\.\d+\.\d+\.\d+',
            r'localhost',
            r'.*\.local',
            r'118\.31\.34\.105',  # 已知的内网地址
        ]
        
        for pattern in internal_patterns:
            if re.search(pattern, url):
                return True
        
        return False


def analyze_with_understanding(target_url: str, session: requests.Session = None) -> AnalysisResult:
    """
    带理解的分析
    
    不是简单地返回 "SPA_FALLBACK"
    而是理解：为什么是 SPA fallback？意味着什么？如何调整策略？
    """
    session = session or requests.Session()
    analyzer = AgenticAnalyzer(session)
    
    print("[*] Phase 1: Observation - 观察多个响应")
    
    # 观察多个不同的 URL
    test_urls = [
        f"{target_url}/login",
        f"{target_url}/admin",
        f"{target_url}/system/swagger.json",
        f"{target_url}/api/v3/api-docs",
        f"{target_url}/api-docs",
        f"{target_url}/swagger.json",
    ]
    
    for url in test_urls:
        try:
            resp = session.get(url, timeout=5, allow_redirects=True)
            obs = analyzer.observe(url, resp)
            
            if obs['is_html']:
                print(f"    [HTML {resp.status_code}] {url}")
                if obs['spa_indicators']:
                    print(f"                 SPA: {', '.join(obs['spa_indicators'][:3])}")
            elif obs['is_json']:
                print(f"    [JSON {resp.status_code}] {url}")
            else:
                print(f"    [{resp.status_code}] {url}")
                
        except Exception as e:
            print(f"    [ERR] {url}: {e}")
    
    print("\n[*] Phase 2: Reasoning - 因果推理")
    
    # 推理
    result = analyzer.reason()
    
    # 从 JS 分析后端地址
    print("\n[*] Phase 3: JS Analysis - 分析 JS 中的后端信息")
    
    try:
        resp = session.get(target_url, timeout=10)
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
        
        js_base_urls = set()
        for js_url in js_urls[:3]:
            if not js_url.startswith('http'):
                js_url = target_url.rstrip('/') + '/' + js_url
            
            try:
                js_resp = session.get(js_url, timeout=10)
                content = js_resp.text
                
                # 提取 baseURL
                base_matches = re.findall(r'(?:baseURL|apiUrl)\s*[:=]\s*["\']([^"\']+)["\']', content)
                js_base_urls.update(base_matches)
                
            except:
                pass
        
        if js_base_urls:
            print(f"    [*] Found base URLs in JS: {js_base_urls}")
            
            js_findings = {
                'base_urls': list(js_base_urls),
                'api_paths': [],
                'sensitive_data': [],
            }
            
            js_result = analyzer.from_js_analysis(js_findings)
            
            # 合并结果
            result.findings.extend(js_result.findings)
            result.unreachable_endpoints.extend(js_result.unreachable_endpoints)
            result.testable_endpoints.extend(js_result.testable_endpoints)
            
            if js_result.findings:
                result.conclusion = js_result.conclusion
                result.adjusted_strategy = js_result.adjusted_strategy
                result.understanding_level = UnderstandingLevel.CAUSAL
                
    except Exception as e:
        print(f"    [!] JS analysis error: {e}")
    
    return result


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://49.65.100.160:6004"
    
    result = analyze_with_understanding(target)
    
    print("\n" + "=" * 70)
    print(" Agentic Analysis Results")
    print("=" * 70)
    
    print(f"\n[*] Understanding Level: {result.understanding_level.value}")
    
    if result.findings:
        print(f"\n[*] Findings (因果分析):")
        for i, f in enumerate(result.findings, 1):
            print(f"\n    [{i}] CONFIDENCE: {f.confidence*100:.0f}%")
            print(f"        WHAT: {f.what}")
            print(f"        SO WHAT: {f.so_what}")
            print(f"        WHY: {f.why}")
            print(f"        IMPLICATION: {f.implication}")
            print(f"        STRATEGY: {f.strategy}")
    
    if result.conclusion:
        print(f"\n[*] CONCLUSION: {result.conclusion}")
    
    if result.adjusted_strategy:
        print(f"\n[*] ADJUSTED STRATEGY:")
        for s in result.adjusted_strategy:
            print(f"    - {s}")
    
    if result.unreachable_endpoints:
        print(f"\n[*] UNREACHABLE ENDPOINTS ({len(result.unreachable_endpoints)}):")
        for ep in result.unreachable_endpoints:
            print(f"    - {ep['url']} ({ep['reason']})")
    
    if result.testable_endpoints:
        print(f"\n[*] TESTABLE ENDPOINTS ({len(result.testable_endpoints)}):")
        for ep in result.testable_endpoints:
            print(f"    - {ep['url']}")
