---
name: misc-challenges
description: Use when encountering 隐写术、取证分析、编码解码、压缩包攻击
---

# 杂项挑战攻击

## Info

- **Domain**: misc
- **Tags**: misc, steganography, forensics, encoding

## 攻击思路
```
文件识别 → 格式分析 → 数据提取 → 隐藏信息解码 → FLAG获取
```

## 文件分析矩阵

| 分析类型 | 工具 | 关键点 |
|----------|------|--------|
| 文件类型 | file, xxd | Magic Number |
| 隐藏数据 | binwalk, foremost | 嵌入文件 |
| 元数据 | exiftool, strings | 作者/时间戳 |
| 结构异常 | hexdump, 010 Editor | 文件头/尾 |

```bash
file mystery.file
binwalk -e mystery.file
foremost -i mystery.file -o output/
exiftool -a mystery.file
strings -n 10 mystery.file
```

## 隐写术攻击

### 图片隐写

| 技术 | 工具 | 特征 |
|------|------|--------|
| LSB隐写 | zsteg, stegsolve | RGB最低位 |
| DCT隐写 | jsteg, stegdetect | JPEG系数 |
| PNG隐写 | pngcheck, zsteg | IDAT/chunk |
| BMP隐写 | stegsolve | 位平面 |

```bash
# PNG/LSB
zsteg -a image.png

# JPEG
jsteg reveal image.jpg output.txt
stegdetect image.jpg

# 通用分析
stegsolve.jar → 打开 → Analyse → LSB/Bit Plane
```

### 音频隐写

| 技术 | 工具 | 特征 |
|------|------|--------|
| 频谱隐写 | Sonic Visualiser | 高频数据 |
| LSB隐写 | audacity, MP3Stego | 波形异常 |
| 相位编码 | 音频分析软件 | 相位变化 |

```bash
# 频谱分析
sox audio.wav -n spectrogram -o spectrogram.png
audacity → 打开 → 频谱视图
```

### 文档隐写

| 技术 | 检测方法 |
|------|----------|
| 零宽字符 | Unicode检测 |
| 空白字符 | 空格/Tab编码 |
| 字体隐藏 | 白色字体/微小字体 |
| PDF水印 | pdftk解压分析 |

```python
# 零宽字符检测
import re
hidden = re.findall(r'[\u200b-\u200f\u2028-\u202f\ufeff]', text)
```

## 编码攻击矩阵

| 编码类型 | 识别特征 | 解码工具 |
|----------|----------|----------|
| Base64 | 结尾有= | base64 -d |
| Base32 | 仅A-Z和2-7 | base32 -d |
| Hex | 0-9A-F偶数长度 | xxd -r -p |
| URL编码 | %XX格式 | Python urllib |
| Morse | .-组合 | 在线工具 |
| Unicode | \uXXXX | Python decode |

### 多层编码攻击
```python
import base64
def decode_layers(data):
    while True:
        try:
            if '=' in data or len(data)%4==0:
                data = base64.b64decode(data).decode()
            elif all(c in '0123456789ABCDEFabcdef' for c in data):
                data = bytes.fromhex(data).decode()
            else:
                break
        except:
            break
    return data
```

## 压缩包攻击

| 攻击类型 | 工具 | 条件 |
|----------|------|--------|
| 伪加密 | zipinfo, 010Editor | 标志位修改 |
| 明文攻击 | pkcrack | 已知明文文件 |
| 密码爆破 | fcrackzip, John | 弱密码 |
| CRC碰撞 | Python脚本 | 短文件CRC |

```bash
# 伪加密检测
zipinfo -v archive.zip
# 修改加密标志位: 010Editor → 50 4B 03 04 → 加密标志

# 明文攻击
pkcrack -C archive.zip -c known.txt -P plain.txt -p known.txt -D decrypted.zip

# 密码爆破
fcrackzip -u -D -p wordlist.txt archive.zip
john --wordlist=rockyou.txt hash.txt
```

## 流量分析

| 分析目标 | 工具 | 方法 |
|----------|------|--------|
| HTTP流量 | Wireshark | Filter: http |
| DNS隧道 | dnscat2, dnsdec | Query解析 |
| TCP数据流 | Wireshark → Follow TCP Stream | 流重组 |
| 无线流量 | aircrack-ng | WEP/WPA破解 |

```bash
# Wireshark过滤
http contains "flag"
tcp.port == 4444
dns.qry.name contains "data"

# 提取文件
tshark -r pcap.pcap --export-objects "http,./output/"
```

## 内存取证

```bash
# Volatility分析
volatility -f memory.dmp imageinfo
volatility -f memory.dmp --profile=Win7SP1x64 pslist
volatility -f memory.dmp --profile=Win7SP1x64 consoles
volatility -f memory.dmp --profile=Win7SP1x64 filescan | grep -i flag
volatility -f memory.dmp --profile=Win7SP1x64 memdump -p PID -D output/
```