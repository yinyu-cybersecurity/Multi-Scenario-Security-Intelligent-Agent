# Business Logic Errors - 业务逻辑漏洞

[SEARCH_KEYWORDS]
漏洞类型: Business Logic Errors Business Logic Flaws 业务逻辑漏洞
攻击类型: Financial Fraud Privilege Escalation Data Manipulation Bypass
关键词: business logic workflow process pricing discount refund cart
测试点: Review Discount Delivery Currency Premium Refund Cart Comment
技术: Race Condition Parameter Manipulation Negative Values CSRF

[CONTENT]

## 业务逻辑漏洞概述

业务逻辑漏洞源于应用程序的业务逻辑，即处理现实世界业务规则和流程的程序部分。这些规则可能包括定价模型、交易限制或多步骤流程的操作顺序。

## 与其他漏洞的区别

业务逻辑漏洞不依赖于代码本身的问题（如未过滤的用户输入），而是利用应用程序的正常预期功能，但以开发人员未预料的方式使用。

## 测试方法论

### 评论功能测试

- 评估是否可以在未购买商品的情况下发布认证评论
- 尝试提供超出标准范围的评分（如0、6或负数）
- 测试同一用户是否可以对单个产品发布多个评分（检测竞争条件）
- 确定文件上传字段是否允许所有扩展名
- 调查冒充其他用户发布评论的可能性
- 尝试CSRF攻击

### 折扣码功能测试

- 尝试多次使用同一折扣码
- 如果折扣码唯一，评估竞争条件（两个账户同时使用）
- 测试批量赋值或HTTP参数污染来应用多个折扣码
- 测试XSS、SQL注入
- 尝试将折扣码应用于非折扣商品

### 配送费操纵

- 实验负值配送费
- 评估是否可以通过修改参数激活免费配送

### 货币套利

- 尝试用一种货币支付（如USD），请求以另一种货币退款（如EUR）
- 汇率差异可能导致利润

### 高级功能利用

- 探索无订阅访问高级账户区域的可能性
- 购买高级功能后取消，查看退款后是否仍可使用
- 查找请求/响应中验证高级访问的true/false值
- 检查cookies或localStorage中验证高级访问的变量

### 退款功能利用

- 购买产品后请求退款，查看产品是否仍可访问
- 寻找货币套利机会
- 提交多个取消请求检查多重退款可能性

### 购物车/愿望清单利用

- 测试负数量产品配合其他产品平衡总额
- 尝试添加超过可用库存的产品数量
- 检查是否可以将产品移动到其他用户的购物车

### 线程评论测试

- 检查线程评论数量限制
- 如果用户只能评论一次，使用竞争条件
- 尝试模仿认证或特权用户参数
- 尝试冒充其他用户发布评论

## 工具

- Burp Suite (Match & Replace)
- 竞争条件测试工具

## 参考文档

原始来源: PayloadsAllTheThings/Business Logic Errors/README.md