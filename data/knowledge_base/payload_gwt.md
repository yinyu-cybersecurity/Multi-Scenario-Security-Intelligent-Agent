# Google Web Toolkit - GWT安全测试

[SEARCH_KEYWORDS]
漏洞类型: Google Web Toolkit GWT Java to JavaScript Web Application Framework
攻击类型: Information Disclosure EL Injection Remote Code Execution
关键词: GWT RPC permutation cache.js nocache.js bootstrap
技术: Method Enumeration RPC Payload Generation Code Backup
工具: GWTMap GWT-Penetration-Testing-Toolset

[CONTENT]

## Google Web Toolkit概述

Google Web Toolkit (GWT)是一套开源工具，允许Web开发人员使用Java创建和维护JavaScript前端应用程序。

## 渗透测试方法论

### 枚举方法

通过bootstrap文件枚举远程应用程序的方法并创建本地备份：

```ps1
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup
```

通过特定代码排列枚举：

```ps1
./gwtmap.py -u http://10.10.10.10/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
```

通过HTTP代理路由流量：

```ps1
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup -p http://127.0.0.1:8080
```

枚举本地副本：

```ps1
./gwtmap.py -F test_data/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
```

### 过滤输出

过滤特定服务或方法：

```ps1
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login
```

### 生成RPC Payload

为过滤服务的所有方法生成RPC payload：

```ps1
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService --rpc --color
```

自动测试RPC请求：

```ps1
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login --rpc --probe
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter TestService.testDetails --rpc --probe
```

## 关键文件

- `*.nocache.js` - Bootstrap文件
- `*.cache.js` - 代码排列文件

## 工具

- GWTMap - 映射GWT应用程序攻击面
- GWT-Penetration-Testing-Toolset - GWT渗透测试工具集

## 参考文档

原始来源: PayloadsAllTheThings/Google Web Toolkit/README.md