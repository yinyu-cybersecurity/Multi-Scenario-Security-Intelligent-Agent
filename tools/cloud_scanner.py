# tools/cloud_scanner.py
"""
云服务扫描器

支持：
- AWS服务枚举
- Azure服务枚举
- GCP服务枚举
- 云存储桶发现
- 敏感信息泄露检测
"""

import os
import json
import subprocess
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from tool_framework import CommandLineTool


@dataclass
class CloudResource:
    """云资源"""
    provider: str
    resource_type: str
    resource_id: str
    region: str = ""
    public: bool = False
    sensitive: bool = False
    details: Dict = None

    def to_dict(self) -> Dict:
        return {
            "provider": self.provider,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "public": self.public,
            "sensitive": self.sensitive,
            "details": self.details or {}
        }


class CloudScanner(CommandLineTool):
    """
    云服务扫描器

    使用多种工具进行云资源发现和安全检查
    """

    def __init__(self):
        super().__init__("cloudscanner")
        self.timeout = 300

    def name(self) -> str:
        return "cloud-scanner"

    def description(self) -> str:
        return "云服务扫描器，支持AWS/Azure/GCP资源发现和安全检查。"

    def supported_vulns(self) -> list:
        return ["Cloud Enumeration", "S3 Bucket", "Azure Blob", "GCS Bucket",
                "Metadata Service", "Cloud Metadata"]

    def check_available(self) -> bool:
        return True

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作: enumerate/s3/azure/gcp/metadata",
                "required": True
            },
            "target": {
                "type": "str",
                "description": "目标域名或IP",
                "required": False
            },
            "keyword": {
                "type": "str",
                "description": "存储桶关键词",
                "required": False
            },
            "provider": {
                "type": "str",
                "description": "云服务商: aws/azure/gcp",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行云扫描"""
        action = params.get("action", "enumerate")

        if action == "enumerate":
            return self._enumerate_cloud(target, params)
        elif action == "s3":
            return self._scan_s3(params)
        elif action == "azure":
            return self._scan_azure(params)
        elif action == "gcp":
            return self._scan_gcp(params)
        elif action == "metadata":
            return self._check_metadata(target)
        else:
            return {"error": f"未知操作: {action}", "success": False}

    # =========================================================================
    # 云服务枚举
    # =========================================================================

    def _enumerate_cloud(self, target: str, params: Dict) -> Dict:
        """
        枚举云服务

        检测目标是否使用云服务，并识别云服务商
        """
        results = {
            "action": "enumerate",
            "target": target,
            "cloud_providers": [],
            "resources": []
        }

        # 检查AWS
        aws_check = self._check_aws(target)
        if aws_check.get("detected"):
            results["cloud_providers"].append("aws")
            results["resources"].extend(aws_check.get("resources", []))

        # 检查Azure
        azure_check = self._check_azure(target)
        if azure_check.get("detected"):
            results["cloud_providers"].append("azure")
            results["resources"].extend(azure_check.get("resources", []))

        # 检查GCP
        gcp_check = self._check_gcp(target)
        if gcp_check.get("detected"):
            results["cloud_providers"].append("gcp")
            results["resources"].extend(gcp_check.get("resources", []))

        results["success"] = len(results["cloud_providers"]) > 0
        return results

    def _check_aws(self, target: str) -> Dict:
        """检查AWS服务"""
        result = {"detected": False, "resources": []}

        # AWS域名特征
        aws_patterns = [
            ".amazonaws.com",
            ".s3.amazonaws.com",
            ".s3-website",
            ".ec2.amazonaws.com",
            ".lambda.amazonaws.com",
            ".rds.amazonaws.com",
            ".cloudfront.net"
        ]

        for pattern in aws_patterns:
            if pattern in target.lower():
                result["detected"] = True
                resource_type = self._guess_aws_resource(pattern)
                result["resources"].append({
                    "provider": "aws",
                    "resource_type": resource_type,
                    "detected_by": pattern
                })
                break

        return result

    def _guess_aws_resource(self, pattern: str) -> str:
        """从URL模式猜测AWS资源类型"""
        mapping = {
            ".s3.amazonaws.com": "S3 Bucket",
            ".s3-website": "S3 Website",
            ".ec2.amazonaws.com": "EC2 Instance",
            ".lambda.amazonaws.com": "Lambda Function",
            ".rds.amazonaws.com": "RDS Database",
            ".cloudfront.net": "CloudFront CDN"
        }
        return mapping.get(pattern, "AWS Resource")

    def _check_azure(self, target: str) -> Dict:
        """检查Azure服务"""
        result = {"detected": False, "resources": []}

        azure_patterns = [
            ".azurewebsites.net",
            ".blob.core.windows.net",
            ".queue.core.windows.net",
            ".table.core.windows.net",
            ".vault.azure.net",
            ".database.windows.net"
        ]

        for pattern in azure_patterns:
            if pattern in target.lower():
                result["detected"] = True
                resource_type = self._guess_azure_resource(pattern)
                result["resources"].append({
                    "provider": "azure",
                    "resource_type": resource_type,
                    "detected_by": pattern
                })
                break

        return result

    def _guess_azure_resource(self, pattern: str) -> str:
        """猜测Azure资源类型"""
        mapping = {
            ".azurewebsites.net": "App Service",
            ".blob.core.windows.net": "Blob Storage",
            ".queue.core.windows.net": "Queue Storage",
            ".table.core.windows.net": "Table Storage",
            ".vault.azure.net": "Key Vault",
            ".database.windows.net": "SQL Database"
        }
        return mapping.get(pattern, "Azure Resource")

    def _check_gcp(self, target: str) -> Dict:
        """检查GCP服务"""
        result = {"detected": False, "resources": []}

        gcp_patterns = [
            ".appspot.com",
            ".storage.googleapis.com",
            ".cloudfunctions.net",
            ".run.app",
            ".cloudsql.googleapis.com"
        ]

        for pattern in gcp_patterns:
            if pattern in target.lower():
                result["detected"] = True
                resource_type = self._guess_gcp_resource(pattern)
                result["resources"].append({
                    "provider": "gcp",
                    "resource_type": resource_type,
                    "detected_by": pattern
                })
                break

        return result

    def _guess_gcp_resource(self, pattern: str) -> str:
        """猜测GCP资源类型"""
        mapping = {
            ".appspot.com": "App Engine",
            ".storage.googleapis.com": "Cloud Storage",
            ".cloudfunctions.net": "Cloud Functions",
            ".run.app": "Cloud Run",
            ".cloudsql.googleapis.com": "Cloud SQL"
        }
        return mapping.get(pattern, "GCP Resource")

    # =========================================================================
    # S3扫描
    # =========================================================================

    def _scan_s3(self, params: Dict) -> Dict:
        """
        S3存储桶扫描

        检测公开访问的S3存储桶
        """
        keyword = params.get("keyword", "")
        results = {
            "action": "s3_scan",
            "keyword": keyword,
            "buckets": []
        }

        # 常见存储桶命名模式
        bucket_names = self._generate_bucket_names(keyword)

        for bucket in bucket_names:
            check = self._check_s3_bucket(bucket)
            if check.get("exists"):
                results["buckets"].append(check)

        results["success"] = len(results["buckets"]) > 0
        return results

    def _generate_bucket_names(self, keyword: str) -> List[str]:
        """生成可能的存储桶名称"""
        if not keyword:
            return []

        names = [
            keyword,
            f"{keyword}-prod",
            f"{keyword}-dev",
            f"{keyword}-test",
            f"{keyword}-backup",
            f"{keyword}-logs",
            f"{keyword}-data",
            f"{keyword}-assets",
            f"{keyword}-static",
            f"{keyword}-media",
            f"{keyword}-config",
            f"{keyword}-secrets",
        ]
        return names

    def _check_s3_bucket(self, bucket_name: str) -> Dict:
        """检查S3存储桶是否存在且公开"""
        result = {
            "name": bucket_name,
            "exists": False,
            "public": False,
            "url": f"https://{bucket_name}.s3.amazonaws.com"
        }

        try:
            # 使用curl检查
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                   f"https://{bucket_name}.s3.amazonaws.com"]

            proc = subprocess.run(cmd, capture_output=True, timeout=10)
            code = proc.stdout.decode().strip()

            if code in ["200", "403"]:
                result["exists"] = True
                result["public"] = (code == "200")

        except Exception:
            pass

        return result

    # =========================================================================
    # Azure扫描
    # =========================================================================

    def _scan_azure(self, params: Dict) -> Dict:
        """Azure资源扫描"""
        keyword = params.get("keyword", "")
        results = {
            "action": "azure_scan",
            "keyword": keyword,
            "resources": []
        }

        # 生成可能的存储账户名称
        account_names = self._generate_azure_names(keyword)

        for name in account_names:
            # 检查Blob存储
            blob_check = self._check_azure_blob(name)
            if blob_check.get("exists"):
                results["resources"].append(blob_check)

        results["success"] = len(results["resources"]) > 0
        return results

    def _generate_azure_names(self, keyword: str) -> List[str]:
        """生成Azure存储账户名称（小写，3-24字符）"""
        if not keyword:
            return []

        base = keyword.lower().replace("-", "")[:21]
        return [
            base,
            f"{base}prod",
            f"{base}dev",
            f"{base}backup",
            f"{base}data"
        ]

    def _check_azure_blob(self, account_name: str) -> Dict:
        """检查Azure Blob存储"""
        result = {
            "name": account_name,
            "exists": False,
            "public": False,
            "url": f"https://{account_name}.blob.core.windows.net"
        }

        try:
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                   f"https://{account_name}.blob.core.windows.net"]

            proc = subprocess.run(cmd, capture_output=True, timeout=10)
            code = proc.stdout.decode().strip()

            if code in ["200", "403", "400"]:
                result["exists"] = True
                result["public"] = (code == "200")

        except Exception:
            pass

        return result

    # =========================================================================
    # GCP扫描
    # =========================================================================

    def _scan_gcp(self, params: Dict) -> Dict:
        """GCP资源扫描"""
        keyword = params.get("keyword", "")
        results = {
            "action": "gcp_scan",
            "keyword": keyword,
            "resources": []
        }

        bucket_names = self._generate_gcs_names(keyword)

        for name in bucket_names:
            check = self._check_gcs_bucket(name)
            if check.get("exists"):
                results["resources"].append(check)

        results["success"] = len(results["resources"]) > 0
        return results

    def _generate_gcs_names(self, keyword: str) -> List[str]:
        """生成GCS存储桶名称"""
        if not keyword:
            return []

        return [
            keyword,
            f"{keyword}-prod",
            f"{keyword}-dev",
            f"{keyword}-backup",
            f"{keyword}-data",
            f"{keyword}-assets"
        ]

    def _check_gcs_bucket(self, bucket_name: str) -> Dict:
        """检查GCS存储桶"""
        result = {
            "name": bucket_name,
            "exists": False,
            "public": False,
            "url": f"https://storage.googleapis.com/{bucket_name}"
        }

        try:
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                   f"https://storage.googleapis.com/{bucket_name}"]

            proc = subprocess.run(cmd, capture_output=True, timeout=10)
            code = proc.stdout.decode().strip()

            if code in ["200", "403", "404"]:
                result["exists"] = (code != "404")
                result["public"] = (code == "200")

        except Exception:
            pass

        return result

    # =========================================================================
    # 元数据服务
    # =========================================================================

    def _check_metadata(self, target: str) -> Dict:
        """
        检查云元数据服务

        尝试访问169.254.169.254获取云实例元数据
        """
        results = {
            "action": "metadata_check",
            "target": target,
            "providers": [],
            "sensitive_data": []
        }

        # AWS元数据
        aws_meta = self._fetch_aws_metadata()
        if aws_meta:
            results["providers"].append("aws")
            results["sensitive_data"].extend(aws_meta)

        # Azure元数据
        azure_meta = self._fetch_azure_metadata()
        if azure_meta:
            results["providers"].append("azure")
            results["sensitive_data"].extend(azure_meta)

        # GCP元数据
        gcp_meta = self._fetch_gcp_metadata()
        if gcp_meta:
            results["providers"].append("gcp")
            results["sensitive_data"].extend(gcp_meta)

        results["success"] = len(results["providers"]) > 0
        return results

    def _fetch_aws_metadata(self) -> List[Dict]:
        """获取AWS元数据"""
        metadata = []

        endpoints = [
            ("/latest/meta-data/iam/security-credentials/", "IAM Role"),
            ("/latest/meta-data/hostname", "Hostname"),
            ("/latest/meta-data/local-ipv4", "Local IP"),
            ("/latest/meta-data/public-ipv4", "Public IP"),
            ("/latest/user-data", "User Data")
        ]

        for endpoint, desc in endpoints:
            try:
                cmd = ["curl", "-s", "--connect-timeout", "3",
                       f"http://169.254.169.254{endpoint}"]

                proc = subprocess.run(cmd, capture_output=True, timeout=5)
                content = proc.stdout.decode().strip()

                if content and not content.startswith("<?xml"):
                    metadata.append({
                        "provider": "aws",
                        "type": desc,
                        "endpoint": endpoint,
                        "value": content[:200]  # 截断敏感信息
                    })

            except Exception:
                pass

        return metadata

    def _fetch_azure_metadata(self) -> List[Dict]:
        """获取Azure元数据"""
        metadata = []

        try:
            cmd = [
                "curl", "-s", "--connect-timeout", "3",
                "-H", "Metadata: true",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
            ]

            proc = subprocess.run(cmd, capture_output=True, timeout=5)
            content = proc.stdout.decode().strip()

            if content:
                try:
                    data = json.loads(content)
                    metadata.append({
                        "provider": "azure",
                        "type": "Instance Metadata",
                        "value": json.dumps(data, indent=2)[:500]
                    })
                except json.JSONDecodeError:
                    pass

        except Exception:
            pass

        return metadata

    def _fetch_gcp_metadata(self) -> List[Dict]:
        """获取GCP元数据"""
        metadata = []

        endpoints = [
            ("/computeMetadata/v1/instance/", "Instance Info"),
            ("/computeMetadata/v1/project/", "Project Info"),
            ("/computeMetadata/v1/instance/service-accounts/", "Service Accounts")
        ]

        for endpoint, desc in endpoints:
            try:
                cmd = [
                    "curl", "-s", "--connect-timeout", "3",
                    "-H", "Metadata-Flavor: Google",
                    f"http://metadata.google.internal{endpoint}"
                ]

                proc = subprocess.run(cmd, capture_output=True, timeout=5)
                content = proc.stdout.decode().strip()

                if content:
                    metadata.append({
                        "provider": "gcp",
                        "type": desc,
                        "endpoint": endpoint,
                        "value": content[:200]
                    })

            except Exception:
                pass

        return metadata


def scan_cloud_metadata() -> Dict:
    """扫描云元数据便捷函数"""
    scanner = CloudScanner()
    return scanner._check_metadata("")


def scan_s3_buckets(keyword: str) -> Dict:
    """S3存储桶扫描便捷函数"""
    scanner = CloudScanner()
    return scanner._scan_s3({"keyword": keyword})


def register():
    """注册云扫描器"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(CloudScanner())