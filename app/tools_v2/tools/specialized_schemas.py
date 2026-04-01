"""
CTF专业方向工具Schema定义

包括：Crypto、Pwn、Reverse、Misc、AI Security、OA Exploit
"""

# ============================================
# Crypto工具 (密码学)
# ============================================

CRYPTO_SCHEMAS = {
    "crypto_identifier": {
        "name": "crypto_identifier",
        "description": "密码学算法识别器，识别加密/编码类型",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ciphertext": {"type": "string", "description": "密文或编码文本"},
                "hint": {"type": "string", "description": "提示信息"}
            },
            "required": ["ciphertext"]
        }
    },
    "classical_cipher_solver": {
        "name": "classical_cipher_solver",
        "description": "古典密码求解器：凯撒、维吉尼亚、栅栏、培根等",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ciphertext": {"type": "string", "description": "密文"},
                "cipher_type": {"type": "string", "enum": ["caesar", "vigenere", "railfence", "bacon", "auto"]},
                "key": {"type": "string", "description": "密钥（可选）"}
            },
            "required": ["ciphertext"]
        }
    },
    "rsa_attacker": {
        "name": "rsa_attacker",
        "description": "RSA攻击工具：小指数、共模、低加密指数等",
        "inputSchema": {
            "type": "object",
            "properties": {
                "n": {"type": "string", "description": "RSA模数n"},
                "e": {"type": "string", "description": "公钥指数e"},
                "c": {"type": "string", "description": "密文c"},
                "attack_type": {"type": "string", "enum": ["small_e", "common_modulus", "low_exponent", "wiener", "factor"]}
            },
            "required": ["n", "e", "c"]
        }
    },
    "hash_analyzer": {
        "name": "hash_analyzer",
        "description": "哈希分析工具：识别哈希类型、碰撞检测、彩虹表查询",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_value": {"type": "string", "description": "哈希值"},
                "mode": {"type": "string", "enum": ["identify", "crack", "compare"]}
            },
            "required": ["hash_value"]
        }
    },
    "encoding_decoder": {
        "name": "encoding_decoder",
        "description": "编码解码工具：Base64、Base32、Hex、URL、HTML等",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "待解码文本"},
                "encoding": {"type": "string", "enum": ["base64", "base32", "hex", "url", "html", "auto"]},
                "mode": {"type": "string", "enum": ["decode", "encode"]}
            },
            "required": ["text"]
        }
    }
}

# ============================================
# Pwn工具 (二进制漏洞)
# ============================================

PWN_SCHEMAS = {
    "binary_analyzer": {
        "name": "binary_analyzer",
        "description": "二进制文件分析器：检测保护、导入导出表、漏洞模式",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "二进制文件路径"},
                "analysis_type": {"type": "string", "enum": ["full", "protection", "functions", "strings"]}
            },
            "required": ["binary_path"]
        }
    },
    "rop_builder": {
        "name": "rop_builder",
        "description": "ROP链构建器：自动搜索gadgets并构造ROP链",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "二进制文件路径"},
                "target": {"type": "string", "description": "目标函数或syscall"},
                "bad_chars": {"type": "string", "description": "坏字符（可选）"}
            },
            "required": ["binary_path"]
        }
    },
    "shellcode_generator": {
        "name": "shellcode_generator",
        "description": "Shellcode生成器：支持多平台多架构",
        "inputSchema": {
            "type": "object",
            "properties": {
                "arch": {"type": "string", "enum": ["x86", "x64", "arm", "arm64", "mips"]},
                "os": {"type": "string", "enum": ["linux", "windows", "freebsd"]},
                "payload_type": {"type": "string", "enum": ["execve", "reverse_shell", "bind_shell", "read_flag"]},
                "custom_command": {"type": "string", "description": "自定义命令"}
            },
            "required": ["arch", "payload_type"]
        }
    },
    "heap_analyzer": {
        "name": "heap_analyzer",
        "description": "堆分析工具：堆风水、堆溢出、UAF检测",
        "inputSchema": {
            "type": "object",
            "properties": {
                "core_dump": {"type": "string", "description": "Core dump文件路径"},
                "analysis_type": {"type": "string", "enum": ["chunks", "bins", "overlap", "uaf"]}
            },
            "required": ["core_dump"]
        }
    },
    "libc_database": {
        "name": "libc_database",
        "description": "Libc数据库查询：根据泄露地址识别Libc版本",
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "符号名称"},
                "address": {"type": "string", "description": "泄露地址"}
            },
            "required": ["symbol", "address"]
        }
    }
}

# ============================================
# Reverse工具 (逆向工程)
# ============================================

REVERSE_SCHEMAS = {
    "disassembler": {
        "name": "disassembler",
        "description": "反汇编工具：支持多种架构的反汇编",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "二进制文件路径"},
                "arch": {"type": "string", "enum": ["x86", "x64", "arm", "mips", "auto"]},
                "start_addr": {"type": "string", "description": "起始地址"},
                "end_addr": {"type": "string", "description": "结束地址"}
            },
            "required": ["binary_path"]
        }
    },
    "decompiler": {
        "name": "decompiler",
        "description": "反编译工具：将二进制转换为伪代码",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "二进制文件路径"},
                "function_addr": {"type": "string", "description": "函数地址"},
                "decompiler_type": {"type": "string", "enum": ["ghidra", "ida", "radare2"]}
            },
            "required": ["binary_path"]
        }
    },
    "string_extractor": {
        "name": "string_extractor",
        "description": "字符串提取工具：提取可打印字符串和Unicode",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "二进制文件路径"},
                "min_length": {"type": "integer", "default": 4, "description": "最小字符串长度"},
                "encoding": {"type": "string", "enum": ["ascii", "utf8", "utf16", "all"]}
            },
            "required": ["binary_path"]
        }
    },
    "apk_analyzer": {
        "name": "apk_analyzer",
        "description": "APK分析工具：反编译、字符串提取、权限分析",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "APK文件路径"},
                "analysis_type": {"type": "string", "enum": ["decompile", "strings", "permissions", "manifest"]}
            },
            "required": ["apk_path"]
        }
    }
}

# ============================================
# Misc工具 (杂项)
# ============================================

MISC_SCHEMAS = {
    "steganography_detector": {
        "name": "steganography_detector",
        "description": "隐写检测工具：检测图片/音频中的隐写数据",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "文件路径"},
                "method": {"type": "string", "enum": ["lsb", "dct", "fft", "all"]}
            },
            "required": ["file_path"]
        }
    },
    "forensics_analyzer": {
        "name": "forensics_analyzer",
        "description": "取证分析工具：内存分析、磁盘分析、文件恢复",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "取证镜像/文件路径"},
                "analysis_type": {"type": "string", "enum": ["memory", "disk", "file_carving", "timeline"]}
            },
            "required": ["file_path"]
        }
    },
    "traffic_analyzer": {
        "name": "traffic_analyzer",
        "description": "流量分析工具：PCAP解析、协议识别、敏感信息提取",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcap_path": {"type": "string", "description": "PCAP文件路径"},
                "filter": {"type": "string", "description": "Wireshark过滤表达式"},
                "extract_mode": {"type": "string", "enum": ["credentials", "files", "images", "all"]}
            },
            "required": ["pcap_path"]
        }
    },
    "encoding_converter": {
        "name": "encoding_converter",
        "description": "编码转换工具：支持多种编码格式互转",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "待转换文本"},
                "from_encoding": {"type": "string", "description": "源编码"},
                "to_encoding": {"type": "string", "description": "目标编码"}
            },
            "required": ["text"]
        }
    },
    "qr_decoder": {
        "name": "qr_decoder",
        "description": "二维码解码工具：识别并解码二维码图片",
        "inputSchema": {
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "二维码图片路径"}
            },
            "required": ["image_path"]
        }
    }
}

# ============================================
# AI Security工具 (AI安全)
# ============================================

AI_SECURITY_SCHEMAS = {
    "ai_attacker": {
        "name": "ai_attacker",
        "description": "AI模型攻击工具：Prompt注入、越狱攻击、模型窃取",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "format": "uri", "description": "AI服务URL"},
                "attack_type": {"type": "string", "enum": ["prompt_inject", "jailbreak", "leak", "extract"]},
                "custom_prompt": {"type": "string", "description": "自定义攻击Prompt"},
                "api_key": {"type": "string", "description": "API密钥（可选）"},
                "model": {"type": "string", "default": "default", "description": "目标模型"}
            },
            "required": ["target_url", "attack_type"]
        }
    },
    "prompt_injector": {
        "name": "prompt_injector",
        "description": "Prompt注入Payload生成器",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_type": {"type": "string", "enum": ["chatgpt", "claude", "llama", "generic"]},
                "payload_type": {"type": "string", "enum": ["ignore_previous", "roleplay", "separator", "encoding"]},
                "goal": {"type": "string", "description": "注入目标"}
            },
            "required": ["payload_type"]
        }
    },
    "model_extractor": {
        "name": "model_extractor",
        "description": "AI模型窃取工具：通过API查询重建模型",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_endpoint": {"type": "string", "format": "uri", "description": "模型API端点"},
                "num_queries": {"type": "integer", "default": 1000, "description": "查询次数"},
                "extract_method": {"type": "string", "enum": ["equation", "active", "pathological"]}
            },
            "required": ["api_endpoint"]
        }
    }
}

# ============================================
# OA Exploit工具 (OA系统攻击)
# ============================================

OA_SCHEMAS = {
    "oa_exploiter": {
        "name": "oa_exploiter",
        "description": "OA系统漏洞利用：泛微/致远/通达/蓝凌等OA历史漏洞",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "format": "uri", "description": "OA系统URL"},
                "oa_type": {"type": "string", "enum": ["weaver", "seeyon", "tongda", "landray", "xinhu", "yonyou", "kingdee", "huatian", "hongfan", "auto"]},
                "vuln_type": {"type": "string", "enum": ["rce", "sql", "sqli", "upload", "ssrf", "all"]},
                "payload": {"type": "string", "description": "自定义Payload"},
                "callback_host": {"type": "string", "description": "回连服务器地址"}
            },
            "required": ["target_url"]
        }
    },
    "weaver_exploit": {
        "name": "weaver_exploit",
        "description": "泛微OA专项漏洞利用",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "format": "uri", "description": "泛微OA URL"},
                "vuln_id": {"type": "string", "description": "漏洞编号或名称"},
                "payload": {"type": "string", "description": "攻击Payload"}
            },
            "required": ["target_url"]
        }
    },
    "seeyon_exploit": {
        "name": "seeyon_exploit",
        "description": "致远OA专项漏洞利用",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "format": "uri", "description": "致远OA URL"},
                "vuln_id": {"type": "string", "description": "漏洞编号"},
                "payload": {"type": "string", "description": "攻击Payload"}
            },
            "required": ["target_url"]
        }
    },
    "tongda_exploit": {
        "name": "tongda_exploit",
        "description": "通达OA专项漏洞利用",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "format": "uri", "description": "通达OA URL"},
                "vuln_id": {"type": "string", "description": "漏洞编号"},
                "payload": {"type": "string", "description": "攻击Payload"}
            },
            "required": ["target_url"]
        }
    }
}

# ============================================
# Cloud Security工具 (云安全)
# ============================================

CLOUD_SCHEMAS = {
    "cloud_scanner": {
        "name": "cloud_scanner",
        "description": "云环境安全扫描：AWS/Azure/GCP/阿里云配置检查",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {"type": "string", "enum": ["aws", "azure", "gcp", "aliyun", "tencent", "auto"]},
                "scan_type": {"type": "string", "enum": ["config", "permissions", "storage", "all"]},
                "region": {"type": "string", "description": "区域"}
            },
            "required": ["provider"]
        }
    },
    "container_escape": {
        "name": "container_escape",
        "description": "容器逃逸检测与利用：Docker/K8s逃逸",
        "inputSchema": {
            "type": "object",
            "properties": {
                "container_id": {"type": "string", "description": "容器ID"},
                "escape_method": {"type": "string", "enum": ["cve", "privilege", "mount", "kernel", "auto"]}
            },
            "required": ["container_id"]
        }
    },
    "kube_attacker": {
        "name": "kube_attacker",
        "description": "Kubernetes攻击工具：未授权访问、提权、容器逃逸",
        "inputSchema": {
            "type": "object",
            "properties": {
                "kube_api": {"type": "string", "format": "uri", "description": "K8s API Server地址"},
                "attack_type": {"type": "string", "enum": ["unauth", "escalate", "escape", "dump"]},
                "namespace": {"type": "string", "description": "命名空间"}
            },
            "required": ["kube_api"]
        }
    },
    "s3_bucket_scanner": {
        "name": "s3_bucket_scanner",
        "description": "S3存储桶扫描器：检测公开访问和敏感数据泄露",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bucket_name": {"type": "string", "description": "存储桶名称"},
                "provider": {"type": "string", "enum": ["aws", "aliyun", "tencent"]},
                "check_type": {"type": "string", "enum": ["permissions", "contents", "all"]}
            },
            "required": ["bucket_name"]
        }
    }
}

# ============================================
# 内网渗透工具补充
# ============================================

INTERNAL_SCHEMAS = {
    "privesc_scanner": {
        "name": "privesc_scanner",
        "description": "提权漏洞扫描：Linux/Windows本地提权检测",
        "inputSchema": {
            "type": "object",
            "properties": {
                "os_type": {"type": "string", "enum": ["linux", "windows", "auto"]},
                "scan_depth": {"type": "string", "enum": ["quick", "full"]}
            },
            "required": []
        }
    },
    "potato_attack": {
        "name": "potato_attack",
        "description": "Potato系列提权工具：Juicy/PrintSpoofer/BadPotato",
        "inputSchema": {
            "type": "object",
            "properties": {
                "attack_type": {"type": "string", "enum": ["juicy", "printspoofer", "badpotato", "roguepotato"]},
                "command": {"type": "string", "description": "要执行的命令"}
            },
            "required": ["attack_type", "command"]
        }
    },
    "ldap_domaindump": {
        "name": "ldap_domaindump",
        "description": "LDAP域信息收集工具",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain_controller": {"type": "string", "description": "域控IP"},
                "username": {"type": "string", "description": "用户名"},
                "password": {"type": "string", "description": "密码"},
                "output_format": {"type": "string", "enum": ["json", "html", "grep"]}
            },
            "required": ["domain_controller"]
        }
    }
}

# 导出所有Schema
ALL_SPECIALIZED_SCHEMAS = {
    **CRYPTO_SCHEMAS,
    **PWN_SCHEMAS,
    **REVERSE_SCHEMAS,
    **MISC_SCHEMAS,
    **AI_SECURITY_SCHEMAS,
    **OA_SCHEMAS,
    **CLOUD_SCHEMAS,
    **INTERNAL_SCHEMAS
}