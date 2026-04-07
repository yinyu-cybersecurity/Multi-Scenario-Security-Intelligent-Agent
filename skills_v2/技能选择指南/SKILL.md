---
name: 技能选择指南
description: Use when encountering 根据目标特征选择攻击技能
---

# 技能选择指南

## Info

- **Domain**: meta
- **Tags**: meta

# 技能选择决策树

## Web应用
```
URL入口 → 信息收集 → 端口扫描 → 目录爆破 → 漏洞探测
                                       ↓
                             按漏洞类型选择技能:
                             - SQL注入 → sqli_*
                             - XSS → xss_*
                             - SSRF → ssrf_*
                             - 文件上传 → rce_*
                             - 反序列化 → php_deserialization/java_deserialization
```

## 内网渗透
```
内网IP → 存活探测 → 端口扫描 → 服务识别
                              ↓
                       按服务选择:
                       - 445: SMB攻击
                       - 3389: RDP攻击
                       - 8080: Web应用
                       - 6379: Redis攻击
                       - 27017: MongoDB
```

## AD域
```
域环境 → BloodHound收集 → 分析攻击路径
                           ↓
                    按权限选择:
                    - 无域用户: AS-REP Roasting
                    - 普通用户: Kerberoasting/委派攻击
                    - 管理员: DCSync/黄金票据
```

## OA系统
```
识别OA类型 → 选择对应技能:
- 泛微 → oa_e-cology
- 用友 → oa_yonyou
- 致远 → oa_seeyon
- 蓝凌 → oa_landray
- 禅道 → oa_zentao
- 通达 → oa_tongda
```

## 云/AI
```
云环境 → SSRF获取元数据
AI应用 → Prompt注入/模型攻击
容器 → 容器逃逸
```