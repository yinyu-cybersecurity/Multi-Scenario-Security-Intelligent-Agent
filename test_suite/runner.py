#!/usr/bin/env python3
# test_suite/runner.py
"""
CTF-Agent 自动化测试运行器
支持批量测试、日志收集、结果统计
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

# 测试题目配置
TEST_CASES = {
    "zone1_basic": {
        "name": "第一赛区：识器·明理",
        "cases": [
            # NSSCTF 题目 - 需要替换为实际URL
            {"name": "EasySQL", "url": None, "type": "sqli", "expected": "flag"},
            {"name": "Havefun", "url": None, "type": "logic", "expected": "flag"},
            {"name": "sql_injection", "url": None, "type": "sqli", "expected": "flag"},
            {"name": "XXE_test", "url": None, "type": "xxe", "expected": "flag"},
            {"name": "Upload_bypass", "url": None, "type": "upload", "expected": "shell"},
            {"name": "Unserialize_pop", "url": None, "type": "deser", "expected": "flag"},
        ]
    },
    "zone2_cve": {
        "name": "第二赛区：洞见·虚实",
        "cases": [
            {"name": "Log4j_RCE", "url": None, "cve": "CVE-2021-44228", "expected": "rce"},
            {"name": "Spring4Shell", "url": None, "cve": "CVE-2022-22965", "expected": "rce"},
            {"name": "Shiro_550", "url": None, "cve": "CVE-2016-4437", "expected": "rce"},
            {"name": "WebLogic_RCE", "url": None, "cve": "CVE-2020-14882", "expected": "rce"},
            {"name": "Tomcat_AJP", "url": None, "cve": "CVE-2020-1938", "expected": "lfi"},
        ]
    },
    "zone3_oa": {
        "name": "第三赛区：执刃·循迹",
        "cases": [
            {"name": "Seeyon_OA", "url": None, "type": "oa", "expected": "shell"},
            {"name": "Weaver_OA", "url": None, "type": "oa", "expected": "shell"},
            {"name": "Tongda_OA", "url": None, "type": "oa", "expected": "shell"},
            {"name": "Yonyou_NC", "url": None, "type": "oa", "expected": "rce"},
        ]
    },
    "zone4_domain": {
        "name": "第四赛区：铸剑·止戈",
        "cases": [
            {"name": "Internal_Network", "url": None, "type": "internal", "expected": "domain_admin"},
        ]
    }
}


class TestRunner:
    """测试运行器"""

    def __init__(self, log_dir: str = None):
        self.log_dir = Path(log_dir or Path(__file__).parent / "logs")
        self.log_dir.mkdir(exist_ok=True)

        self.results = {
            "start_time": datetime.now().isoformat(),
            "zones": {},
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "timeout": 0
            }
        }

    def run_single_test(self, case: Dict, timeout: int = 600) -> Dict:
        """运行单个测试用例"""
        result = {
            "name": case.get("name"),
            "url": case.get("url"),
            "type": case.get("type"),
            "start_time": datetime.now().isoformat(),
            "status": "pending",
            "flag": None,
            "shell": None,
            "vulnerabilities": [],
            "errors": [],
            "raw_log": ""
        }

        if not case.get("url"):
            result["status"] = "skipped"
            result["errors"].append("URL未配置")
            return result

        print(f"\n{'='*60}")
        print(f"[Test] {case['name']} - {case.get('url', 'N/A')}")
        print(f"{'='*60}")

        # 构建命令
        cmd = [
            sys.executable,
            str(Path(__file__).parent.parent / "ctf_agent_graph.py"),
            "--target", case["url"],
            "--skip"  # 跳过自检加速测试
        ]

        if case.get("type") == "internal":
            cmd.append("--mode")
            cmd.append("internal")

        try:
            # 运行测试
            start_time = time.time()

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(Path(__file__).parent.parent)
            )

            output_lines = []
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    output_lines.append(line)
                    print(line, end='')  # 实时输出

                # 检查超时
                if time.time() - start_time > timeout:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    result["status"] = "timeout"
                    result["errors"].append(f"执行超时 ({timeout}s)")
                    break

            result["raw_log"] = "".join(output_lines)
            result["return_code"] = process.returncode

            if result["status"] != "timeout":
                # 分析结果
                result = self._analyze_result(result, case)

        except Exception as e:
            result["status"] = "error"
            result["errors"].append(str(e))
            # 确保清理进程
            if process and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except:
                    try:
                        process.kill()
                    except:
                        pass

        result["end_time"] = datetime.now().isoformat()
        return result

    def _analyze_result(self, result: Dict, case: Dict) -> Dict:
        """分析测试结果"""
        log = result["raw_log"]
        expected = case.get("expected", "flag")

        # 检查是否找到flag
        if "flag{" in log.lower() or "ctf{" in log.lower():
            result["flag"] = self._extract_flag(log)
            result["status"] = "passed"
            return result

        # 检查是否获取shell
        if "shell_obtained" in log.lower() or "webshell" in log.lower():
            result["shell"] = True
            if expected == "shell":
                result["status"] = "passed"
                return result

        # 检查漏洞发现
        if "vulnerable: true" in log.lower():
            result["status"] = "partial"  # 发现漏洞但未完全利用
            return result

        # 检查失败原因
        if "no vulnerability found" in log.lower():
            result["status"] = "failed"
            result["errors"].append("未发现漏洞")
        elif "max retries" in log.lower():
            result["status"] = "failed"
            result["errors"].append("达到最大重试次数")
        elif "timeout" in log.lower():
            result["status"] = "timeout"
        else:
            result["status"] = "unknown"

        return result

    def _extract_flag(self, log: str) -> str:
        """从日志中提取flag"""
        import re
        patterns = [
            r'flag\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'FLAG\{[^}]+\}',
        ]
        for pattern in patterns:
            match = re.search(pattern, log, re.IGNORECASE)
            if match:
                return match.group(0)
        return ""

    def run_zone(self, zone_id: str) -> Dict:
        """运行一个赛区的所有测试"""
        zone = TEST_CASES.get(zone_id, {})
        cases = zone.get("cases", [])

        print(f"\n{'#'*60}")
        print(f"# {zone.get('name', zone_id)}")
        print(f"# 共 {len(cases)} 个测试用例")
        print(f"{'#'*60}")

        zone_results = {
            "name": zone.get("name"),
            "total": len(cases),
            "passed": 0,
            "failed": 0,
            "timeout": 0,
            "skipped": 0,
            "cases": []
        }

        for case in cases:
            result = self.run_single_test(case)
            zone_results["cases"].append(result)

            if result["status"] == "passed":
                zone_results["passed"] += 1
            elif result["status"] == "timeout":
                zone_results["timeout"] += 1
            elif result["status"] == "skipped":
                zone_results["skipped"] += 1
            else:
                zone_results["failed"] += 1

            # 保存单个测试日志
            log_file = self.log_dir / f"{case['name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(result["raw_log"])

        return zone_results

    def run_all(self, zones: List[str] = None):
        """运行所有测试"""
        zones = zones or list(TEST_CASES.keys())

        for zone_id in zones:
            if zone_id in TEST_CASES:
                self.results["zones"][zone_id] = self.run_zone(zone_id)

        # 汇总结果
        self.results["end_time"] = datetime.now().isoformat()

        for zone_id, zone_data in self.results["zones"].items():
            self.results["summary"]["total"] += zone_data.get("total", 0)
            self.results["summary"]["passed"] += zone_data.get("passed", 0)
            self.results["summary"]["failed"] += zone_data.get("failed", 0)
            self.results["summary"]["timeout"] += zone_data.get("timeout", 0)

        # 保存结果
        result_file = self.log_dir / f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(result_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)

        self._print_summary()
        return self.results

    def _print_summary(self):
        """打印测试总结"""
        print(f"\n{'='*60}")
        print("测试总结")
        print(f"{'='*60}")

        for zone_id, zone_data in self.results["zones"].items():
            print(f"\n{zone_data['name']}:")
            print(f"  总计: {zone_data['total']}")
            print(f"  通过: {zone_data['passed']}")
            print(f"  失败: {zone_data['failed']}")
            print(f"  超时: {zone_data['timeout']}")
            print(f"  跳过: {zone_data['skipped']}")

        print(f"\n{'='*60}")
        s = self.results["summary"]
        print(f"总计: {s['total']} | 通过: {s['passed']} | 失败: {s['failed']} | 超时: {s['timeout']}")
        pass_rate = (s['passed'] / s['total'] * 100) if s['total'] > 0 else 0
        print(f"通过率: {pass_rate:.1f}%")
        print(f"{'='*60}")


def interactive_config():
    """交互式配置测试用例"""
    print("\n" + "="*60)
    print("CTF-Agent 测试配置")
    print("="*60)

    for zone_id, zone in TEST_CASES.items():
        print(f"\n## {zone['name']}")
        for case in zone["cases"]:
            url = input(f"  {case['name']} URL (回车跳过): ").strip()
            if url:
                case["url"] = url

    # 保存配置
    config_file = Path(__file__).parent / "test_config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(TEST_CASES, f, ensure_ascii=False, indent=2)

    print(f"\n配置已保存到: {config_file}")
    return TEST_CASES


def load_config():
    """加载测试配置"""
    config_file = Path(__file__).parent / "test_config.json"
    if config_file.exists():
        with open(config_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return TEST_CASES


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CTF-Agent 测试运行器")
    parser.add_argument("--config", action="store_true", help="交互式配置测试用例")
    parser.add_argument("--zone", type=str, help="指定测试赛区 (zone1/zone2/zone3/zone4)")
    parser.add_argument("--target", type=str, help="直接测试单个目标")
    parser.add_argument("--timeout", type=int, default=600, help="单个测试超时时间(秒)")

    args = parser.parse_args()

    runner = TestRunner()

    if args.config:
        interactive_config()
    elif args.target:
        # 单目标测试
        case = {"name": "custom_test", "url": args.target}
        result = runner.run_single_test(case, timeout=args.timeout)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.zone:
        # 指定赛区测试
        TEST_CASES.update(load_config())
        runner.results["zones"][args.zone] = runner.run_zone(args.zone)
        runner._print_summary()
    else:
        # 运行所有测试
        TEST_CASES.update(load_config())
        runner.run_all()