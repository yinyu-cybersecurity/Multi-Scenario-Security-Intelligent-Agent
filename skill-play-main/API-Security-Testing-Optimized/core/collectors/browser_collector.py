#!/usr/bin/env python3
"""
Browser Collector - 浏览器动态采集器
使用无头浏览器采集动态渲染的 JS、API 请求等
"""

import time
import json
from typing import Dict, List, Set, Optional, Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

try:
    from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


@dataclass
class BrowserResource:
    """浏览器资源"""
    url: str
    resource_type: str
    method: str = "GET"
    request_headers: Dict = field(default_factory=dict)
    response_headers: Dict = field(default_factory=dict)
    post_data: Optional[str] = None
    response_body: Optional[str] = None
    status_code: int = 0
    content_length: int = 0


@dataclass
class BrowserCollectionResult:
    """浏览器采集结果"""
    js_urls: List[str] = field(default_factory=list)
    api_requests: List[BrowserResource] = field(default_factory=list)
    static_resources: List[BrowserResource] = field(default_factory=list)
    websocket_connections: List[str] = field(default_factory=list)
    xhr_requests: List[BrowserResource] = field(default_factory=list)
    fetched_urls: Set[str] = field(default_factory=set)


class HeadlessBrowserCollector:
    """
    无头浏览器采集器
    
    功能:
    - 动态 JS 采集
    - API 请求捕获 (XHR/Fetch)
    - WebSocket 连接捕获
    - 静态资源采集
    - 页面截图
    - 控制台日志捕获
    """
    
    def __init__(self, headless: bool = True, timeout: int = 30000):
        self.headless = headless
        self.timeout = timeout
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page = None
        self.resources: List[BrowserResource] = []
        self.api_requests: List[BrowserResource] = []
        self.ws_connections: List[str] = []
        self.console_logs: List[str] = []
        self.js_urls: Set[str] = set()
    
    def start(self) -> bool:
        """启动浏览器"""
        if not HAS_PLAYWRIGHT:
            print("[!] Playwright not installed. Run: pip install playwright")
            return False
        
        try:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(
                headless=self.headless,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-blink-features=AutomationControlled'
                ]
            )
            self.context = self.browser.new_context(
                ignore_https_errors=True,
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            self.page = self.context.new_page()
            self._setup_listeners()
            return True
        except Exception as e:
            print(f"[!] Browser start failed: {e}")
            return False
    
    def _setup_listeners(self):
        """设置请求监听"""
        if not self.page:
            return
        
        def on_request(request):
            resource = BrowserResource(
                url=request.url,
                resource_type=request.resource_type,
                method=request.method,
                request_headers=dict(request.headers),
                post_data=request.post_data
            )
            self.resources.append(resource)
            
            if request.resource_type == 'script':
                self.js_urls.add(request.url)
            
            if request.resource_type in ['xhr', 'fetch']:
                self.api_requests.append(resource)
        
        def on_response(response):
            for resource in self.resources:
                if resource.url == response.url:
                    resource.status_code = response.status
                    resource.response_headers = dict(response.headers)
                    try:
                        resource.content_length = len(response.body)
                    except:
                        pass
        
        def on_websocket(ws):
            self.ws_connections.append(ws.url)
        
        def on_console(msg):
            self.console_logs.append(f"[{msg.type}] {msg.text}")
        
        self.page.on("request", on_request)
        self.page.on("response", on_response)
        self.page.on("websocket", on_websocket)
        self.page.on("console", on_console)
    
    def navigate(self, url: str, wait_for_selector: Optional[str] = None, delay: int = 0) -> bool:
        """导航到 URL"""
        if not self.page:
            return False
        
        try:
            self.page.goto(url, timeout=self.timeout)
            
            if delay > 0:
                time.sleep(delay)
            
            if wait_for_selector:
                try:
                    self.page.wait_for_selector(wait_for_selector, timeout=self.timeout)
                except:
                    pass
            else:
                self.page.wait_for_load_state("networkidle", timeout=self.timeout)
            
            return True
        except Exception as e:
            print(f"[!] Navigation failed: {e}")
            return False
    
    def click_and_intercept(self, selector: str, intercept_api: bool = True) -> bool:
        """点击元素并拦截 API 请求"""
        if not self.page:
            return False
        
        try:
            self.page.click(selector)
            time.sleep(1)
            return True
        except Exception as e:
            print(f"[!] Click failed: {e}")
            return False
    
    def fill_form_and_submit(self, form_data: Dict[str, str], submit_selector: str = "button[type='submit']") -> bool:
        """填写表单并提交"""
        if not self.page:
            return False
        
        try:
            for field_name, value in form_data.items():
                try:
                    self.page.fill(f"input[name='{field_name}']", value)
                except:
                    try:
                        self.page.fill(f"textarea[name='{field_name}']", value)
                    except:
                        pass
            
            time.sleep(0.5)
            self.page.click(submit_selector)
            time.sleep(2)
            return True
        except Exception as e:
            print(f"[!] Form submit failed: {e}")
            return False
    
    def execute_script(self, script: str) -> any:
        """执行 JavaScript"""
        if not self.page:
            return None
        
        try:
            return self.page.evaluate(script)
        except Exception as e:
            print(f"[!] Script execution failed: {e}")
            return None
    
    def get_dynamic_js_urls(self) -> List[str]:
        """获取动态加载的 JS URL"""
        return list(self.js_urls)
    
    def get_api_requests(self) -> List[BrowserResource]:
        """获取 API 请求"""
        return self.api_requests
    
    def get_websocket_connections(self) -> List[str]:
        """获取 WebSocket 连接"""
        return self.ws_connections
    
    def get_console_logs(self) -> List[str]:
        """获取控制台日志"""
        return self.console_logs
    
    def get_local_storage(self) -> Dict[str, str]:
        """获取 localStorage"""
        if not self.page:
            return {}
        
        try:
            return self.page.evaluate("() => JSON.stringify(localStorage)")
        except:
            return {}
    
    def get_session_storage(self) -> Dict[str, str]:
        """获取 sessionStorage"""
        if not self.page:
            return {}
        
        try:
            return self.page.evaluate("() => JSON.stringify(sessionStorage)")
        except:
            return {}
    
    def get_cookies(self) -> List[Dict]:
        """获取 Cookies"""
        if not self.context:
            return []
        
        try:
            return [dict(c) for c in self.context.cookies()]
        except:
            return []
    
    def screenshot(self, path: str, full_page: bool = False) -> bool:
        """页面截图"""
        if not self.page:
            return False
        
        try:
            self.page.screenshot(path=path, full_page=full_page)
            return True
        except Exception as e:
            print(f"[!] Screenshot failed: {e}")
            return False
    
    def stop(self):
        """停止浏览器"""
        try:
            if self.browser:
                self.browser.close()
            if hasattr(self, 'playwright'):
                self.playwright.stop()
        except:
            pass
    
    def collect(self, target_url: str, interactions: List[Dict] = None) -> BrowserCollectionResult:
        """
        执行完整采集流程
        
        Args:
            target_url: 目标 URL
            interactions: 交互列表，如 [{"type": "click", "selector": ".btn"}, ...]
        """
        result = BrowserCollectionResult()
        
        if not self.start():
            return result
        
        try:
            print(f"[*] Navigating to {target_url}")
            self.navigate(target_url)
            result.fetched_urls.add(target_url)
            
            for js_url in self.get_dynamic_js_urls():
                result.js_urls.append(js_url)
            
            result.api_requests.extend(self.get_api_requests())
            result.websocket_connections.extend(self.get_websocket_connections())
            
            if interactions:
                for action in interactions:
                    action_type = action.get('type')
                    
                    if action_type == 'click':
                        self.click_and_intercept(action.get('selector', ''))
                    elif action_type == 'fill':
                        self.fill_form_and_submit(
                            action.get('data', {}),
                            action.get('submit', "button[type='submit']")
                        )
                    elif action_type == 'navigate':
                        url = action.get('url')
                        if url:
                            self.navigate(url)
                            result.fetched_urls.add(url)
                    elif action_type == 'wait':
                        time.sleep(action.get('seconds', 1))
            
            for js_url in self.get_dynamic_js_urls():
                if js_url not in result.js_urls:
                    result.js_urls.append(js_url)
            
            result.api_requests.extend(self.get_api_requests())
            
        finally:
            self.stop()
        
        return result


class BrowserCollectorFacade:
    """浏览器采集器门面 - 统一接口"""
    
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.collector = HeadlessBrowserCollector(headless=headless)
    
    def collect_all(self, target_url: str, config: Dict = None) -> Dict:
        """
        执行完整采集
        
        Args:
            target_url: 目标 URL
            config: 配置
                - interactions: 交互列表
                - capture_console: 是否捕获控制台
                - capture_storage: 是否捕获存储
                - screenshot: 是否截图
        """
        config = config or {}
        interactions = config.get('interactions', [])
        
        result = self.collector.collect(target_url, interactions)
        
        output = {
            'target_url': target_url,
            'js_urls': result.js_urls,
            'api_requests': [
                {
                    'url': r.url,
                    'method': r.method,
                    'type': r.resource_type,
                    'post_data': r.post_data,
                    'status_code': r.status_code,
                }
                for r in result.api_requests
            ],
            'websocket_connections': result.websocket_connections,
            'fetched_urls': list(result.fetched_urls),
            'console_logs': self.collector.get_console_logs() if config.get('capture_console') else [],
            'cookies': self.collector.get_cookies() if config.get('capture_storage') else [],
        }
        
        if config.get('screenshot'):
            screenshot_path = f"/tmp/screenshot_{int(time.time())}.png"
            if self.collector.screenshot(screenshot_path):
                output['screenshot'] = screenshot_path
        
        return output


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Browser Collector")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--headless", action="store_true", default=True)
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--screenshot", action="store_true")
    
    args = parser.parse_args()
    
    facade = BrowserCollectorFacade(headless=args.headless)
    result = facade.collect_all(args.target, {
        'capture_console': True,
        'screenshot': args.screenshot
    })
    
    print("\n=== Collection Results ===")
    print(f"Target: {result['target_url']}")
    print(f"JS URLs found: {len(result['js_urls'])}")
    print(f"API requests: {len(result['api_requests'])}")
    print(f"WebSocket connections: {len(result['websocket_connections'])}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\nResults saved to {args.output}")
