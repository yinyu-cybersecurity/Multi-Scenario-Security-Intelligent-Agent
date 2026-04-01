#!/usr/bin/env python3
"""
API Fuzzer - API 路径模糊测试器
基于发现的 API 路径，生成变体探测隐藏端点
"""

import re
import time
from typing import List, Set, Dict, Tuple, Optional
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
import requests


@dataclass
class FuzzResult:
    """Fuzzing 结果"""
    path: str
    method: str = "GET"
    status_code: int = 0
    content_length: int = 0
    is_alive: bool = False
    is_new: bool = False
    response_time: float = 0.0


class APIfuzzer:
    """
    API 路径模糊测试器
    
    功能:
    - 父路径探测 (parent_path + suffix)
    - RESTful 路径生成
    - 路径参数化测试
    - 跨来源路径组合
    """
    
    # RESTful 常见后缀
    RESTFUL_SUFFIXES = [
        'list', 'get', 'add', 'create', 'update', 'edit', 'delete', 'remove',
        'detail', 'info', 'view', 'show', 'query', 'search', 'fetch', 'load',
        'save', 'submit', 'export', 'import', 'upload', 'download',
        'config', 'setting', 'settings', 'options', 'permissions', 'all',
    ]
    
    # 常见资源名
    COMMON_RESOURCES = [
        'user', 'users', 'product', 'products', 'order', 'orders',
        'admin', 'auth', 'login', 'logout', 'register', 'profile',
        'config', 'setting', 'settings', 'menu', 'role', 'permission',
        'department', 'organ', 'organization', 'company', 'employee',
    ]
    
    # 常见路径前缀
    COMMON_PREFIXES = [
        '/api', '/v1', '/v2', '/v3', '/rest', '/restful',
        '/admin', '/user', '/auth', '/service', '/web', '/mobile',
    ]
    
    # 危险路径关键字 (跳过测试)
    DANGEROUS_KEYWORDS = [
        'delete', 'remove', 'drop', 'truncate', 'shutdown', 'kill',
        'exec', 'eval', 'shell', 'cmd', 'backup', 'restore',
    ]
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/html, */*',
            'Accept-Encoding': 'gzip, deflate',
        })
        
        self.found_endpoints: List[FuzzResult] = []
        self.tested_paths: Set[str] = set()
    
    def generate_parent_fuzz_targets(self, api_paths: List[str], max_per_parent: int = 20) -> List[str]:
        """
        基于父路径生成 Fuzz 目标
        
        Args:
            api_paths: 已发现的 API 路径列表
            max_per_parent: 每个父路径最多生成的目标数
        
        Returns:
            Fuzz 目标路径列表
        """
        targets = []
        parent_map = {}
        
        for path in api_paths:
            if not path or len(path) < 2:
                continue
            
            path = path.strip()
            parts = path.strip('/').split('/')
            
            for i in range(1, len(parts)):
                parent = '/' + '/'.join(parts[:i])
                if parent not in parent_map:
                    parent_map[parent] = []
                if i < len(parts):
                    child = parts[i]
                    if child not in parent_map[parent]:
                        parent_map[parent].append(child)
        
        for parent, children in parent_map.items():
            targets.append(parent)
            
            for suffix in self.RESTFUL_SUFFIXES[:10]:
                if len(targets) >= max_per_parent * len(parent_map):
                    break
                targets.append(f"{parent}/{suffix}")
            
            for child in children[:5]:
                if child in self.RESTFUL_SUFFIXES:
                    continue
                targets.append(f"{parent}/{child}")
                for suffix in self.RESTFUL_SUFFIXES[:5]:
                    targets.append(f"{parent}/{child}/{suffix}")
        
        return list(set(targets))[:500]
    
    def generate_cross_source_targets(self, js_paths: List[str], html_paths: List[str], api_paths: List[str]) -> List[str]:
        """
        跨来源组合路径
        
        将不同来源的路径片段智能组合探测隐藏 API
        
        Args:
            js_paths: JS 中发现的路径
            html_paths: HTML 中发现的路径
            api_paths: API 中发现的路径
        
        Returns:
            组合后的测试目标
        """
        all_segments: Set[str] = set()
        
        for path_list in [js_paths, html_paths, api_paths]:
            for path in path_list:
                parts = path.strip('/').split('/')
                for part in parts:
                    if part and not part.startswith('{') and not part.isdigit():
                        if len(part) > 1:
                            all_segments.add(part)
        
        targets = []
        
        for prefix in self.COMMON_PREFIXES[:5]:
            for segment in list(all_segments)[:30]:
                if segment.lower() not in [p.lower() for p in self.COMMON_PREFIXES]:
                    targets.append(f"{prefix}/{segment}")
                    for suffix in self.RESTFUL_SUFFIXES[:5]:
                        targets.append(f"{prefix}/{segment}/{suffix}")
        
        return list(set(targets))[:200]
    
    def generate_parameter_fuzz_targets(self, endpoints: List[Dict], params: List[str]) -> List[Tuple[str, Dict]]:
        """
        生成参数 Fuzz 目标
        
        Args:
            endpoints: 端点列表
            params: 参数名列表
        
        Returns:
            (url, params) 元组列表
        """
        targets = []
        
        common_values = {
            'id': ['1', '0', '999999', '-1', "1' OR '1'='1"],
            'page': ['1', '0', '999'],
            'pageSize': ['10', '50', '100', '9999'],
            'userId': ['1', '0', 'admin', "admin'--"],
            'type': ['1', '0', 'admin', 'test'],
            'search': ["' OR '1'='1", '<script>alert(1)</script>', '${jndi}'],
            'q': ["' OR '1'='1", '<script>alert(1)</script>'],
        }
        
        for endpoint in endpoints[:50]:
            path = endpoint.get('path', endpoint.get('url', ''))
            method = endpoint.get('method', 'GET')
            
            if not path:
                continue
            
            for param in params[:10]:
                value = common_values.get(param, ['1', 'test', 'admin'])
                for v in value[:3]:
                    targets.append((path, {param: v}))
        
        return targets[:500]
    
    def fuzz_paths(self, base_url: str, paths: List[str], 
                   methods: List[str] = None,
                   timeout: float = 5.0,
                   skip_dangerous: bool = True) -> List[FuzzResult]:
        """
        执行路径 Fuzzing
        
        Args:
            base_url: 基础 URL
            paths: 路径列表
            methods: HTTP 方法列表
            timeout: 超时时间
            skip_dangerous: 跳过危险路径
        
        Returns:
            Fuzz 结果列表
        """
        methods = methods or ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']
        results = []
        
        for path in paths:
            if path in self.tested_paths:
                continue
            
            if skip_dangerous and any(k in path.lower() for k in self.DANGEROUS_KEYWORDS):
                continue
            
            self.tested_paths.add(path)
            full_url = urljoin(base_url, path)
            
            for method in methods:
                try:
                    start_time = time.time()
                    resp = self.session.request(
                        method,
                        full_url,
                        timeout=timeout,
                        allow_redirects=False
                    )
                    response_time = time.time() - start_time
                    
                    result = FuzzResult(
                        path=path,
                        method=method,
                        status_code=resp.status_code,
                        content_length=len(resp.content),
                        is_alive=resp.status_code < 500,
                        is_new=resp.status_code not in [301, 302, 404],
                        response_time=response_time
                    )
                    results.append(result)
                    self.found_endpoints.append(result)
                    
                except requests.exceptions.Timeout:
                    results.append(FuzzResult(
                        path=path, method=method, status_code=0, 
                        is_alive=False, response_time=timeout
                    ))
                except Exception:
                    pass
        
        return results
    
    def fuzz_with_params(self, base_url: str, targets: List[Tuple[str, Dict]],
                         timeout: float = 5.0) -> List[FuzzResult]:
        """
        执行带参数的 Fuzzing
        
        Args:
            base_url: 基础 URL
            targets: (path, params) 元组列表
            timeout: 超时时间
        
        Returns:
            Fuzz 结果列表
        """
        results = []
        
        for path, params in targets:
            full_url = urljoin(base_url, path)
            
            try:
                start_time = time.time()
                resp = self.session.post(
                    full_url,
                    json=params,
                    timeout=timeout,
                    allow_redirects=False
                )
                response_time = time.time() - start_time
                
                result = FuzzResult(
                    path=f"{path} (POST JSON {params})",
                    method='POST',
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    is_alive=resp.status_code < 500,
                    is_new=resp.status_code not in [301, 302, 404],
                    response_time=response_time
                )
                results.append(result)
                self.found_endpoints.append(result)
                
            except Exception:
                pass
        
        return results
    
    def get_alive_endpoints(self) -> List[FuzzResult]:
        """获取存活的端点"""
        return [r for r in self.found_endpoints if r.is_alive and r.status_code not in [301, 302]]
    
    def get_high_value_endpoints(self) -> List[FuzzResult]:
        """获取高价值端点 (非标准状态码)"""
        return [r for r in self.found_endpoints if r.is_new]
    
    def get_summary(self) -> Dict:
        """获取 Fuzzing 结果摘要"""
        alive = self.get_alive_endpoints()
        high_value = self.get_high_value_endpoints()
        
        status_counts = {}
        for r in self.found_endpoints:
            status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
        
        return {
            'total_tested': len(self.tested_paths),
            'total_results': len(self.found_endpoints),
            'alive_endpoints': len(alive),
            'high_value_endpoints': len(high_value),
            'status_distribution': status_counts,
            'avg_response_time': sum(r.response_time for r in self.found_endpoints) / max(len(self.found_endpoints), 1)
        }


def auto_fuzz(target_url: str, api_paths: List[str] = None, 
              js_content: str = None, html_content: str = None,
              session: requests.Session = None) -> Dict:
    """
    自动 Fuzzing 流程
    
    Args:
        target_url: 目标 URL
        api_paths: 已发现的 API 路径
        js_content: JS 文件内容
        html_content: HTML 内容
    
    Returns:
        Fuzzing 结果
    """
    api_paths = api_paths or []
    session = session or requests.Session()
    
    fuzzer = APIfuzzer(session=session)
    
    all_paths = set(api_paths)
    
    if js_content:
        js_api_patterns = [
            r"['\"](/api/[^'\"\\\s]+)['\"]",
            r"['\"](/v\d+/[^'\"\\\s]+)['\"]",
            r"baseURL\s*[:=]\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in js_api_patterns:
            matches = re.findall(pattern, js_content)
            all_paths.update(matches)
    
    if html_content:
        html_patterns = [
            r"href=['\"](/[^'\"]+)['\"]",
            r"src=['\"](/[^'\"]+\.js)['\"]",
        ]
        for pattern in html_patterns:
            matches = re.findall(pattern, html_content)
            all_paths.update(matches)
    
    parent_targets = fuzzer.generate_parent_fuzz_targets(list(all_paths))
    
    cross_targets = []
    if js_content and html_content:
        cross_targets = fuzzer.generate_cross_source_targets(
            js_paths=api_paths,
            html_paths=[],
            api_paths=api_paths
        )
    
    all_targets = list(set(parent_targets + cross_targets))
    
    print(f"[*] Generated {len(all_targets)} fuzz targets")
    
    results = fuzzer.fuzz_paths(target_url, all_targets[:200], timeout=3.0)
    
    summary = fuzzer.get_summary()
    
    return {
        'targets_generated': len(all_targets),
        'endpoints_tested': summary['total_tested'],
        'alive_endpoints': summary['alive_endpoints'],
        'high_value_endpoints': summary['high_value_endpoints'],
        'results': results,
        'summary': summary
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="API Fuzzer")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--paths", help="File with API paths")
    parser.add_argument("--output", help="Output file")
    
    args = parser.parse_args()
    
    session = requests.Session()
    result = auto_fuzz(args.target, session=session)
    
    print(f"\n[*] Fuzzing Summary:")
    print(f"    Targets: {result['targets_generated']}")
    print(f"    Tested: {result['endpoints_tested']}")
    print(f"    Alive: {result['alive_endpoints']}")
    print(f"    High Value: {result['high_value_endpoints']}")
    
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
