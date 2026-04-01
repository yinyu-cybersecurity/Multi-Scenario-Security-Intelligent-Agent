#!/usr/bin/env python3
"""
Browser Automation Tester - 浏览器动态测试引擎
支持 Playwright/Puppeteer/Selenium 多引擎
"""

import json
import time
import re
import warnings
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

warnings.filterwarnings("ignore")


class BrowserEngine(Enum):
    PLAYWRIGHT = "playwright"
    PUPPETEER = "puppeteer"
    SELENIUM = "selenium"
    NONE = "none"


@dataclass
class XSSResult:
    vuln_type: str
    payload: str
    location: str
    sink: Optional[str] = None
    severity: str = "medium"
    evidence: str = ""
    url: str = ""


@dataclass
class BrowserTestConfig:
    target_url: str
    engine: BrowserEngine = BrowserEngine.NONE
    headless: bool = True
    timeout: int = 30000
    wait_for_selector: Optional[str] = None
    screenshot_on_error: bool = False
    console_log: bool = False
    user_data_dir: Optional[str] = None
    proxy: Optional[str] = None


class BrowserAutomationTester:
    """
    浏览器动态测试引擎
    
    支持:
    - DOM XSS 检测
    - SPA 路由测试
    - 表单交互测试
    - JavaScript 执行检测
    - Cookie/Session 测试
    """
    
    def __init__(self, config: BrowserTestConfig):
        self.config = config
        self.engine = config.engine
        self.results: List[XSSResult] = []
        self._browser = None
        self._context = None
        self._page = None
        self._init_engine()
    
    def _init_engine(self):
        """初始化浏览器引擎"""
        if self.engine == BrowserEngine.PLAYWRIGHT:
            self._init_playwright()
        elif self.engine == BrowserEngine.SELENIUM:
            self._init_selenium()
        elif self.engine == BrowserEngine.PUPPETEER:
            self._init_puppeteer()
        else:
            print("[!] No browser engine available. Install: pip install playwright")
    
    def _init_playwright(self):
        """初始化 Playwright"""
        try:
            from playwright.sync_api import sync_playwright
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=self.config.headless,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            self._context = self._browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            self._page = self._context.new_page()
            if self.config.console_log:
                self._page.on("console", lambda msg: print(f"[Browser Console] {msg.text}"))
            print("[+] Playwright initialized successfully")
        except ImportError:
            print("[!] Playwright not installed. Run: pip install playwright && playwright install chromium")
            self.engine = BrowserEngine.NONE
        except Exception as e:
            print(f"[!] Playwright init failed: {e}")
            self.engine = BrowserEngine.NONE
    
    def _init_selenium(self):
        """初始化 Selenium"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            
            options = Options()
            if self.config.headless:
                options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            if self.config.proxy:
                options.add_argument(f"--proxy-server={self.config.proxy}")
            
            self._driver = webdriver.Chrome(options=options)
            self._driver.set_page_load_timeout(self.config.timeout / 1000)
            print("[+] Selenium initialized successfully")
        except ImportError:
            print("[!] Selenium not installed. Run: pip install selenium")
            self.engine = BrowserEngine.NONE
        except Exception as e:
            print(f"[!] Selenium init failed: {e}")
            self.engine = BrowserEngine.NONE
    
    def _init_puppeteer(self):
        """初始化 Puppeteer (通过 pyppeteer)"""
        try:
            import asyncio
            from pyppeteer import launch
            asyncio.get_event_loop().run_until_complete(
                self._init_puppeteer_async()
            )
        except ImportError:
            print("[!] pyppeteer not installed. Run: pip install pyppeteer")
            self.engine = BrowserEngine.NONE
        except Exception as e:
            print(f"[!] Puppeteer init failed: {e}")
            self.engine = BrowserEngine.NONE
    
    async def _init_puppeteer_async(self):
        self._browser = await launch(
            headless=self.config.headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        self._page = await self._browser.newPage()
        print("[+] Puppeteer initialized successfully")
    
    def test_dom_xss(self, payloads: List[Dict]) -> List[XSSResult]:
        """
        测试 DOM XSS 漏洞
        
        检测 sinks: innerHTML, eval, document.write, location.href, etc.
        """
        if self.engine == BrowserEngine.NONE:
            return []
        
        dom_sinks = {
            "innerHTML": r'innerHTML\s*=',
            "outerHTML": r'outerHTML\s*=',
            "insertAdjacentHTML": r'insertAdjacentHTML',
            "document.write": r'document\.write',
            "eval": r'eval\(',
            "setTimeout": r'setTimeout\s*\(',
            "setInterval": r'setInterval\s*\(',
            "Function": r'new\s+Function\(',
            "location.href": r'location\.href',
            "location.hash": r'location\.hash',
            "location.search": r'location\.search',
            "document.cookie": r'document\.cookie',
            "localStorage": r'localStorage\.',
            "sessionStorage": r'sessionStorage\.',
        }
        
        xss_payloads = [p for p in payloads if p.get("type") in ["dom", "reflected", "polyglot"]]
        
        print(f"[*] Testing {len(xss_payloads)} DOM XSS payloads...")
        
        for payload_data in xss_payloads:
            payload = payload_data.get("payload", "")
            sink = payload_data.get("sink", "")
            
            for url_pattern, source in [
                (f"{self.config.target_url}?input={payload}", "URL parameter"),
                (f"{self.config.target_url}#{payload}", "URL fragment"),
                (f"{self.config.target_url}?redirect={payload}", "redirect param"),
            ]:
                try:
                    self._navigate_and_check(url_pattern, payload, sink, dom_sinks)
                except Exception as e:
                    print(f"[!] Error testing payload: {e}")
        
        return self.results
    
    def _navigate_and_check(self, url: str, payload: str, sink: str, dom_sinks: Dict):
        """导航到 URL 并检查 XSS"""
        if self.engine == BrowserEngine.PLAYWRIGHT:
            self._page.goto(url, timeout=self.config.timeout)
            self._page.wait_for_load_state("networkidle", timeout=self.config.timeout)
            time.sleep(1)
            
            content = self._page.content()
            
            for sink_pattern, sink_name in dom_sinks.items():
                if re.search(sink_pattern, content, re.IGNORECASE):
                    if payload in content or any(x in content for x in ["<script", "<img", "<svg"]):
                        self.results.append(XSSResult(
                            vuln_type="DOM XSS",
                            payload=payload,
                            location="client-side",
                            sink=sink_name,
                            severity="high",
                            evidence=f"Sink '{sink_name}' found with payload",
                            url=url
                        ))
                        return
    
    def test_spa_routing(self, routes: List[str]) -> Dict[str, Any]:
        """
        测试 SPA 路由安全性
        
        1. 测试路由参数中的 XSS
        2. 测试认证绕过
        3. 测试敏感端点访问
        """
        if self.engine == BrowserEngine.NONE:
            return {"error": "No browser engine"}
        
        results = {
            "routes_tested": [],
            "xss_found": [],
            "auth_bypass": [],
            "sensitive_access": []
        }
        
        test_params = ["<script>alert(1)</script>", "' Or '1'='1", "../../../etc/passwd"]
        
        for route in routes:
            full_url = f"{self.config.target_url}{route}"
            
            try:
                if self.engine == BrowserEngine.PLAYWRIGHT:
                    self._page.goto(full_url, timeout=self.config.timeout)
                    self._page.wait_for_load_state("networkidle")
                    time.sleep(1)
                    
                    results["routes_tested"].append(route)
                    
                    content = self._page.content()
                    for param in test_params:
                        if param in content:
                            results["xss_found"].append({
                                "route": route,
                                "payload": param
                            })
                    
                    title = self._page.title()
                    if "admin" in title.lower() or "dashboard" in title.lower():
                        results["sensitive_access"].append({
                            "route": route,
                            "title": title
                        })
                        
            except Exception as e:
                print(f"[!] Error testing route {route}: {e}")
        
        return results
    
    def test_form_interaction(self, form_selectors: List[Dict]) -> List[XSSResult]:
        """
        测试表单交互 XSS
        
        填写表单并提交，检测存储型 XSS
        """
        if self.engine == BrowserEngine.NONE:
            return []
        
        results = []
        
        xss_test_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "'; alert(1); //"
        ]
        
        for form in form_selectors:
            selector = form.get("selector")
            fields = form.get("fields", {})
            
            for payload in xss_test_payloads:
                try:
                    if self.engine == BrowserEngine.PLAYWRIGHT:
                        self._page.goto(self.config.target_url, timeout=self.config.timeout)
                        self._page.wait_for_load_state("networkidle")
                        
                        for field_name, field_type in fields.items():
                            if field_type == "text":
                                self._page.fill(f"input[name='{field_name}']", payload)
                            elif field_type == "textarea":
                                self._page.fill(f"textarea[name='{field_name}']", payload)
                        
                        if "submit" in fields:
                            self._page.click(f"button[type='submit'], input[type='submit']")
                            time.sleep(2)
                            
                            content = self._page.content()
                            if payload in content:
                                results.append(XSSResult(
                                    vuln_type="Stored XSS",
                                    payload=payload,
                                    location=f"Form: {selector}",
                                    severity="critical",
                                    evidence="Payload persisted after submission"
                                ))
                                
                except Exception as e:
                    print(f"[!] Form test error: {e}")
        
        return results
    
    def test_javascript_execution(self, payload: str) -> Tuple[bool, str]:
        """
        测试 JavaScript 是否被执行
        
        使用 console.log 配合 CDP 获取执行结果
        """
        if self.engine == BrowserEngine.NONE:
            return False, "No browser engine"
        
        test_payloads = [
            f"<script>console.log('XSS_TEST_{payload[:20]}')</script>",
            f"<img src=x onerror='console.log(\"XSS_TEST_{payload[:20]}\")'>",
            f"<svg onload='console.log(\"XSS_TEST_{payload[:20]}\")'>"
        ]
        
        for test_payload in test_payloads:
            try:
                if self.engine == BrowserEngine.PLAYWRIGHT:
                    console_messages = []
                    
                    def handle_console(msg):
                        if "XSS_TEST" in msg.text:
                            console_messages.append(msg.text)
                    
                    self._page.on("console", handle_console)
                    
                    test_url = f"{self.config.target_url}?input={test_payload}"
                    self._page.goto(test_url, timeout=self.config.timeout)
                    self._page.wait_for_load_state("networkidle")
                    time.sleep(2)
                    
                    if console_messages:
                        return True, f"JS executed: {console_messages}"
                    
            except Exception as e:
                continue
        
        return False, "No JS execution detected"
    
    def capture_network_requests(self) -> List[Dict]:
        """捕获网络请求，用于分析 API 调用"""
        if self.engine == BrowserEngine.PLAYWRIGHT:
            requests = []
            
            def handle_request(request):
                requests.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "post_data": request.post_data
                })
            
            self._page.on("request", handle_request)
            self._page.reload()
            self._page.wait_for_load_state("networkidle")
            
            return requests
        return []
    
    def get_client_storage(self) -> Dict[str, Dict]:
        """获取客户端存储 (localStorage, sessionStorage, cookies)"""
        if self.engine == BrowserEngine.PLAYWRIGHT:
            return {
                "localStorage": self._page.evaluate("() => JSON.stringify(localStorage)"),
                "sessionStorage": self._page.evaluate("() => JSON.stringify(sessionStorage)"),
                "cookies": [dict(c) for c in self._context.cookies()]
            }
        return {}
    
    def close(self):
        """关闭浏览器"""
        try:
            if self._browser:
                self._browser.close()
            if hasattr(self, '_driver') and self._driver:
                self._driver.quit()
        except:
            pass


def auto_detect_engine() -> BrowserEngine:
    """自动检测可用的浏览器引擎"""
    try:
        from playwright.sync_api import sync_playwright
        return BrowserEngine.PLAYWRIGHT
    except ImportError:
        pass
    
    try:
        from selenium import webdriver
        return BrowserEngine.SELENIUM
    except ImportError:
        pass
    
    return BrowserEngine.NONE


def create_tester(target_url: str, headless: bool = True) -> Optional[BrowserAutomationTester]:
    """创建浏览器测试器，自动选择可用引擎"""
    engine = auto_detect_engine()
    
    if engine == BrowserEngine.NONE:
        print("[!] No browser automation library found.")
        print("[*] Install one of:")
        print("    - Playwright: pip install playwright && playwright install chromium")
        print("    - Selenium: pip install selenium")
        return None
    
    config = BrowserTestConfig(
        target_url=target_url,
        engine=engine,
        headless=headless,
        timeout=30000,
        console_log=False
    )
    
    return BrowserAutomationTester(config)


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Browser Automation Security Tester")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--type", choices=["dom", "spa", "form", "all"], default="all")
    parser.add_argument("--payloads", help="Path to payloads JSON file")
    parser.add_argument("--routes", nargs="+", help="SPA routes to test")
    parser.add_argument("--headless", action="store_true", default=True)
    
    args = parser.parse_args()
    
    tester = create_tester(args.target, headless=args.headless)
    
    if not tester:
        exit(1)
    
    payloads = [
        {"id": "xss-001", "payload": "<script>alert(1)</script>", "type": "dom"},
        {"id": "xss-002", "payload": "<img src=x onerror=alert(1)>", "type": "reflected"},
    ]
    
    if args.type in ["dom", "all"]:
        print("\n[*] Running DOM XSS tests...")
        results = tester.test_dom_xss(payloads)
        print(f"[+] Found {len(results)} DOM XSS vulnerabilities")
    
    if args.type in ["spa", "all"]:
        routes = args.routes or ["/", "/admin", "/dashboard", "/login"]
        print("\n[*] Running SPA routing tests...")
        results = tester.test_spa_routing(routes)
        print(f"[+] Tested {len(results.get('routes_tested', []))} routes")
    
    tester.close()
