# 供应链攻击

## 1. 拼写抢注(Typosquatting)

```
npm install express
npm install exprees (假包)
```

## 2. 依赖混淆

```
// 私有包名
@company/internal-api
```

## 3. CI/CD投毒

```
.github/workflows/ci.yml
植入恶意代码
```

## 4. 恶意依赖

```
依赖包含后门
```

## 5. 代码签名

```
使用伪造证书签名
```

## 6. 社区攻击

```
发布恶意npm包
社会工程学
```
