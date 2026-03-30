# misc/tools.py
"""
Misc工具集

提供隐写术、取证、编码等功能
"""

import re
import os
import struct
import subprocess
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

# 兼容本地开发和Docker环境
try:
    from app.flag_extractor_v2 import extract_flags
except ImportError:
    from flag_extractor_v2 import extract_flags

# 延迟导入避免循环依赖
def _get_llm_client():
    """获取LLM客户端实例"""
    try:
        from llm_client import llm_client
        return llm_client
    except ImportError:
        return None

def _get_config():
    """获取配置"""
    try:
        from config import config
        return config
    except ImportError:
        return None


class FileType(Enum):
    """文件类型"""
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    ARCHIVE = "archive"
    DOCUMENT = "document"
    BINARY = "binary"
    PCAP = "pcap"
    UNKNOWN = "unknown"


@dataclass
class FileInfo:
    """文件信息"""
    path: str
    file_type: FileType
    mime_type: str
    size: int
    hash_md5: str
    hash_sha256: str
    metadata: Dict[str, Any]


class SteganographyDetector:
    """
    隐写术检测器

    检测和提取各种隐写术
    """

    # 文件签名
    SIGNATURES = {
        'png': b'\x89PNG\r\n\x1a\n',
        'jpg': b'\xff\xd8\xff',
        'gif': b'GIF8',
        'bmp': b'BM',
        'zip': b'PK\x03\x04',
        'rar': b'Rar!',
        'pdf': b'%PDF',
        'elf': b'\x7fELF',
        'wav': b'RIFF',
        'avi': b'RIFF',
    }

    @classmethod
    def detect_file_type(cls, file_path: str) -> Tuple[str, bytes]:
        """检测文件真实类型"""
        with open(file_path, 'rb') as f:
            header = f.read(16)

        for ext, sig in cls.SIGNATURES.items():
            if header.startswith(sig):
                return ext, header

        return 'unknown', header

    @classmethod
    def check_file_trailer(cls, file_path: str) -> Optional[bytes]:
        """检查文件尾部附加数据"""
        detected_type, header = cls.detect_file_type(file_path)

        if detected_type == 'jpg':
            return cls._check_jpg_trailer(file_path)
        elif detected_type == 'png':
            return cls._check_png_trailer(file_path)
        elif detected_type == 'gif':
            return cls._check_gif_trailer(file_path)

        return None

    @classmethod
    def _check_jpg_trailer(cls, file_path: str) -> Optional[bytes]:
        """检查JPG尾部"""
        with open(file_path, 'rb') as f:
            data = f.read()

        # 找到FF D9结束标记后的数据
        end_marker = b'\xff\xd9'
        pos = data.rfind(end_marker)

        if pos != -1 and pos + 2 < len(data):
            return data[pos + 2:]

        return None

    @classmethod
    def _check_png_trailer(cls, file_path: str) -> Optional[bytes]:
        """检查PNG尾部"""
        with open(file_path, 'rb') as f:
            data = f.read()

        # 找到IEND块后的数据
        iend = b'IEND'
        pos = data.find(iend)

        if pos != -1:
            # IEND块结束位置
            end_pos = pos + 4 + 4 + 4  # CRC(4) + IEND(4) + CRC(4)
            if end_pos < len(data):
                return data[end_pos:]

        return None

    @classmethod
    def _check_gif_trailer(cls, file_path: str) -> Optional[bytes]:
        """检查GIF尾部"""
        with open(file_path, 'rb') as f:
            data = f.read()

        # 找到0x3B结束标记后的数据
        end_marker = b'\x3b'
        pos = data.rfind(end_marker)

        if pos != -1 and pos + 1 < len(data):
            return data[pos + 1:]

        return None

    @classmethod
    def extract_lsb(cls, file_path: str) -> Optional[bytes]:
        """提取LSB隐写数据"""
        try:
            from PIL import Image
            img = Image.open(file_path)

            bits = []
            pixels = list(img.getdata())

            for pixel in pixels:
                if isinstance(pixel, int):
                    pixel = (pixel,)
                for channel in pixel[:3]:  # RGB
                    bits.append(channel & 1)

            # 转换为字节
            extracted = []
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                extracted.append(byte)

            # 查找可打印内容
            result = bytes(extracted)
            # 尝试找到flag
            flag_match = re.search(rb'flag\{[^\}]+\}', result)
            if flag_match:
                return flag_match.group()

            return result[:500]  # 限制输出

        except ImportError:
            print("[Steganography] PIL not available")
            return None
        except Exception as e:
            print(f"[Steganography] LSB extraction error: {e}")
            return None

    @classmethod
    def check_exif_data(cls, file_path: str) -> Dict:
        """检查EXIF数据"""
        exif_data = {}

        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            img = Image.open(file_path)
            exif = img._getexif()

            if exif:
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    exif_data[str(tag)] = str(value)

        except Exception:
            pass

        return exif_data

    @classmethod
    def ai_detect_steganography(cls, file_path: str, file_info: Dict = None) -> Dict:
        """
        使用AI动态识别隐写术并决定提取策略

        Args:
            file_path: 文件路径
            file_info: 文件基本信息（可选）

        Returns:
            隐写检测结果和提取建议
        """
        # 收集文件分析数据
        analysis_data = cls._collect_file_analysis(file_path)

        # 调用AI进行识别
        return cls._ai_detect_steganography(analysis_data, file_info)

    @classmethod
    def _collect_file_analysis(cls, file_path: str) -> Dict:
        """收集文件分析数据供AI判断"""
        analysis = {
            'file_path': file_path,
            'detected_type': None,
            'header_hex': None,
            'trailer_data': None,
            'embedded_signatures': [],
            'exif_data': {},
            'file_size': 0,
            'image_dimensions': None,
            'suspicious_patterns': []
        }

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            analysis['file_size'] = len(data)
            analysis['header_hex'] = data[:32].hex()

            # 检测文件类型
            detected_type, header = cls.detect_file_type(file_path)
            analysis['detected_type'] = detected_type

            # 检查尾部数据
            trailer = cls.check_file_trailer(file_path)
            if trailer:
                analysis['trailer_data'] = {
                    'hex': trailer[:50].hex(),
                    'length': len(trailer),
                    'printable_ratio': sum(1 for b in trailer[:100] if 32 <= b <= 126) / min(len(trailer), 100)
                }

            # 查找嵌入签名
            embedded_sigs = cls._find_all_signatures(data)
            analysis['embedded_signatures'] = embedded_sigs

            # 检查EXIF（如果是图片）
            if detected_type in ['png', 'jpg', 'gif', 'bmp']:
                analysis['exif_data'] = cls.check_exif_data(file_path)

            # 获取图片尺寸
            try:
                from PIL import Image
                img = Image.open(file_path)
                analysis['image_dimensions'] = img.size
                analysis['image_mode'] = img.mode
            except Exception:
                pass

            # 查找可疑模式
            analysis['suspicious_patterns'] = cls._find_suspicious_patterns(data)

        except Exception as e:
            analysis['error'] = str(e)

        return analysis

    @classmethod
    def _find_all_signatures(cls, data: bytes) -> List[Dict]:
        """查找所有嵌入的文件签名"""
        signatures = []

        sig_patterns = [
            ('ZIP', b'PK\x03\x04'),
            ('RAR', b'Rar!'),
            ('PDF', b'%PDF'),
            ('PNG', b'\x89PNG'),
            ('JPG', b'\xff\xd8\xff'),
            ('ELF', b'\x7fELF'),
            ('PE', b'MZ'),
            ('7Z', b'7z\xbc\xaf'),
        ]

        for name, sig in sig_patterns:
            pos = 0
            while True:
                pos = data.find(sig, pos)
                if pos == -1:
                    break
                # 跳过文件头的第一个签名
                if pos > 0:
                    signatures.append({
                        'type': name,
                        'offset': hex(pos),
                        'context': data[pos:pos+20].hex()
                    })
                pos += 1

        return signatures[:10]  # 限制数量

    @classmethod
    def _find_suspicious_patterns(cls, data: bytes) -> List[Dict]:
        """查找可疑模式"""
        patterns = []

        # 查找flag相关字符串 - 使用统一的提取函数
        try:
            text = data.decode('utf-8', errors='ignore')
            found_flags = extract_flags(text)
            for flag in found_flags:
                # 查找flag在原始数据中的位置
                flag_bytes = flag.encode('utf-8')
                pos = data.find(flag_bytes)
                patterns.append({
                    'type': 'flag_string',
                    'value': flag,
                    'offset': hex(pos) if pos >= 0 else 'unknown'
                })
        except Exception:
            pass

        # 查找高熵区域（可能是加密/压缩数据）
        chunk_size = 256
        for i in range(0, len(data) - chunk_size, chunk_size):
            chunk = data[i:i+chunk_size]
            entropy = cls._calculate_entropy(chunk)
            if entropy > 7.5:  # 高熵
                patterns.append({
                    'type': 'high_entropy',
                    'offset': hex(i),
                    'entropy': round(entropy, 2)
                })

        # 查找Base64模式
        b64_pattern = rb'[A-Za-z0-9+/]{20,}={0,2}'
        for match in re.finditer(b64_pattern, data):
            candidate = match.group()
            if len(candidate) >= 20:
                patterns.append({
                    'type': 'base64_candidate',
                    'offset': hex(match.start()),
                    'length': len(candidate)
                })

        return patterns[:20]  # 限制数量

    @classmethod
    def _calculate_entropy(cls, data: bytes) -> float:
        """计算数据熵"""
        import math
        if not data:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        for count in freq.values():
            prob = count / len(data)
            entropy -= prob * math.log2(prob)

        return entropy

    @classmethod
    def _ai_detect_steganography(cls, analysis_data: Dict, file_info: Dict = None) -> Dict:
        """
        使用AI动态决定隐写提取策略

        根据文件特征让AI判断可能的隐写方式，而非依赖硬编码的检测规则。
        """
        llm_client = _get_llm_client()
        config = _get_config()

        if not llm_client or not config:
            return {'error': 'LLM client not available', 'method': 'fallback'}

        # 构建分析上下文
        context = f"""## File Analysis Data
- File Path: {analysis_data.get('file_path', 'unknown')}
- File Size: {analysis_data.get('file_size', 0)} bytes
- Detected Type: {analysis_data.get('detected_type', 'unknown')}
- Header (hex): {analysis_data.get('header_hex', 'N/A')}
"""

        if file_info:
            context += f"- MIME Type: {file_info.get('mime', 'unknown')}\n"

        # 尾部数据
        if analysis_data.get('trailer_data'):
            td = analysis_data['trailer_data']
            context += f"""## Trailer Data Found
- Length: {td.get('length', 0)} bytes after normal EOF
- Printable Ratio: {td.get('printable_ratio', 0):.2f}
- Hex Preview: {td.get('hex', '')[:100]}
"""

        # 嵌入签名
        if analysis_data.get('embedded_signatures'):
            context += f"""## Embedded File Signatures
{json.dumps(analysis_data['embedded_signatures'], indent=2)}
"""

        # 图片信息
        if analysis_data.get('image_dimensions'):
            context += f"""## Image Properties
- Dimensions: {analysis_data.get('image_dimensions')}
- Mode: {analysis_data.get('image_mode', 'unknown')}
"""

        # 可疑模式
        if analysis_data.get('suspicious_patterns'):
            context += f"""## Suspicious Patterns Found
{json.dumps(analysis_data['suspicious_patterns'][:10], indent=2)}
"""

        prompt = f"""
You are a steganography expert analyzing a file for hidden data.

{context}

## Task
Analyze the file characteristics and determine:
1. What type of steganography is most likely used
2. The best extraction strategy
3. Priority order for extraction attempts

## Common Steganography Techniques to Consider
- LSB (Least Significant Bit) embedding in images
- File appended after normal EOF (trailer data)
- Hidden files embedded within the file (polyglot files)
- EXIF/metadata hiding
- Palette manipulation in indexed images
- Spectrogram hiding in audio
- File structure manipulation (PNG chunks, etc.)
- Encrypted hidden data

## Output Format (JSON)
{{
  "steganography_type": "primary type detected or 'none' if no clear indication",
  "confidence": 0.0-1.0,
  "extraction_strategy": {{
    "primary_method": "method name (lsb/trailer/extract_embedded/exif/etc)",
    "parameters": {{"key": "value"}},
    "secondary_methods": ["backup method 1", "backup method 2"]
  }},
  "findings": ["list of suspicious findings"],
  "recommendations": ["actionable extraction steps"]
}}

Only output valid JSON. Be precise about extraction parameters.
"""

        try:
            response = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )

            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]

            result = json.loads(response.strip())
            result['analysis_data'] = analysis_data  # 包含原始分析数据
            return result

        except json.JSONDecodeError as e:
            print(f"[SteganographyDetector] AI detection JSON parse error: {e}")
            return {'error': str(e), 'method': 'fallback', 'analysis_data': analysis_data}
        except Exception as e:
            print(f"[SteganographyDetector] AI detection error: {e}")
            return {'error': str(e), 'method': 'fallback', 'analysis_data': analysis_data}


class ForensicsAnalyzer:
    """
    取证分析器

    分析文件和内存取证
    """

    @classmethod
    def analyze_file(cls, file_path: str) -> FileInfo:
        """
        分析文件信息

        Args:
            file_path: 文件路径

        Returns:
            文件信息
        """
        import hashlib

        # 计算哈希
        with open(file_path, 'rb') as f:
            data = f.read()

        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        # 检测MIME类型
        mime_type = cls._detect_mime(file_path, data[:16])

        # 确定文件类型
        file_type = cls._determine_file_type(mime_type, data[:16])

        # 提取元数据
        metadata = cls._extract_metadata(file_path, file_type)

        return FileInfo(
            path=file_path,
            file_type=file_type,
            mime_type=mime_type,
            size=len(data),
            hash_md5=md5,
            hash_sha256=sha256,
            metadata=metadata
        )

    @classmethod
    def _detect_mime(cls, file_path: str, header: bytes) -> str:
        """检测MIME类型"""
        mimes = {
            b'\x89PNG': 'image/png',
            b'\xff\xd8\xff': 'image/jpeg',
            b'GIF8': 'image/gif',
            b'BM': 'image/bmp',
            b'PK\x03\x04': 'application/zip',
            b'Rar!': 'application/x-rar',
            b'%PDF': 'application/pdf',
            b'\x7fELF': 'application/x-elf',
            b'MZ': 'application/x-dosexec',
        }

        for sig, mime in mimes.items():
            if header.startswith(sig):
                return mime

        return 'application/octet-stream'

    @classmethod
    def _determine_file_type(cls, mime_type: str, header: bytes) -> FileType:
        """确定文件类型枚举"""
        if 'image' in mime_type:
            return FileType.IMAGE
        elif 'audio' in mime_type:
            return FileType.AUDIO
        elif 'video' in mime_type:
            return FileType.VIDEO
        elif 'zip' in mime_type or 'rar' in mime_type:
            return FileType.ARCHIVE
        elif 'pdf' in mime_type:
            return FileType.DOCUMENT
        elif 'elf' in mime_type or 'dosexec' in mime_type:
            return FileType.BINARY

        return FileType.UNKNOWN

    @classmethod
    def _extract_metadata(cls, file_path: str, file_type: FileType) -> Dict:
        """提取元数据"""
        metadata = {}

        # 基本文件信息
        stat = os.stat(file_path)
        metadata['size'] = stat.st_size
        metadata['modified'] = stat.st_mtime
        metadata['created'] = stat.st_ctime

        # 使用file命令
        try:
            result = subprocess.run(
                ['file', file_path],
                capture_output=True, text=True, timeout=10
            )
            metadata['file_command'] = result.stdout.strip()
        except Exception:
            pass

        # 使用strings命令
        try:
            result = subprocess.run(
                ['strings', '-n', '8', file_path],
                capture_output=True, text=True, timeout=30
            )
            strings = result.stdout.split('\n')[:50]
            metadata['strings'] = strings
        except Exception:
            pass

        return metadata

    @classmethod
    def find_embedded_files(cls, file_path: str) -> List[Dict]:
        """查找嵌入的文件"""
        embedded = []

        with open(file_path, 'rb') as f:
            data = f.read()

        # 查找常见文件签名
        patterns = [
            ('ZIP', b'PK\x03\x04'),
            ('RAR', b'Rar!'),
            ('PDF', b'%PDF'),
            ('PNG', b'\x89PNG'),
            ('JPG', b'\xff\xd8\xff'),
            ('ELF', b'\x7fELF'),
            ('PE', b'MZ'),
        ]

        for name, sig in patterns:
            pos = 0
            while True:
                pos = data.find(sig, pos)
                if pos == -1:
                    break
                embedded.append({
                    'type': name,
                    'offset': hex(pos),
                    'signature': sig.hex()
                })
                pos += 1

        return embedded


class MediaAnalyzer:
    """
    媒体文件分析器

    分析图片、音频、视频
    """

    @classmethod
    def analyze_image(cls, file_path: str) -> Dict:
        """分析图片"""
        result = {
            'type': 'image',
            'format': None,
            'size': None,
            'mode': None,
            'palette': None,
            'comments': []
        }

        try:
            from PIL import Image
            img = Image.open(file_path)

            result['format'] = img.format
            result['size'] = img.size
            result['mode'] = img.mode

            # 检查调色板
            if img.palette:
                result['palette'] = 'present'

            # 检查注释
            if hasattr(img, 'info'):
                for key, value in img.info.items():
                    result['comments'].append(f"{key}: {value}")

        except ImportError:
            print("[MediaAnalyzer] PIL not available")
        except Exception as e:
            print(f"[MediaAnalyzer] Image analysis error: {e}")

        return result

    @classmethod
    def analyze_audio(cls, file_path: str) -> Dict:
        """分析音频"""
        result = {
            'type': 'audio',
            'format': None,
            'duration': None,
            'sample_rate': None,
            'channels': None
        }

        try:
            # 尝试使用mutagen或pydub
            import mutagen
            audio = mutagen.File(file_path)

            if audio:
                result['format'] = type(audio).__name__
                result['duration'] = audio.info.length if hasattr(audio, 'info') else None
                result['sample_rate'] = audio.info.sample_rate if hasattr(audio, 'info') else None

        except ImportError:
            # 使用ffprobe
            try:
                result = subprocess.run(
                    ['ffprobe', '-v', 'quiet', '-print_format', 'json',
                     '-show_format', '-show_streams', file_path],
                    capture_output=True, text=True, timeout=30
                )
                # 解析JSON输出
                import json
                probe_data = json.loads(result.stdout)
                result['format'] = probe_data.get('format', {}).get('format_name')
            except Exception:
                pass
        except Exception as e:
            print(f"[MediaAnalyzer] Audio analysis error: {e}")

        return result

    @classmethod
    def check_spectrogram(cls, file_path: str) -> Optional[str]:
        """检查频谱图隐写"""
        # 这需要生成频谱图并分析
        # 简化实现，返回提示
        return "Spectrogram analysis available with sox: sox audio.wav -n spectrogram"


class TrafficAnalyzer:
    """
    流量分析器

    分析pcap文件
    """

    @classmethod
    def analyze_pcap(cls, file_path: str) -> Dict:
        """分析pcap文件"""
        result = {
            'packet_count': 0,
            'protocols': {},
            'hosts': [],
            'http_requests': [],
            'dns_queries': [],
            'potential_secrets': []
        }

        try:
            # 使用tshark分析
            cmd = ['tshark', '-r', file_path, '-q', '-z', 'conv,ip']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            result['hosts'] = proc.stdout.split('\n')[:20]

            # HTTP请求
            cmd = ['tshark', '-r', file_path, '-Y', 'http.request', '-T', 'fields',
                   '-e', 'http.host', '-e', 'http.request.uri']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            result['http_requests'] = proc.stdout.split('\n')[:50]

            # DNS查询
            cmd = ['tshark', '-r', file_path, '-Y', 'dns.qry.name', '-T', 'fields',
                   '-e', 'dns.qry.name']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            result['dns_queries'] = proc.stdout.split('\n')[:50]

            # 统计协议
            cmd = ['tshark', '-r', file_path, '-q', '-z', 'io,phs']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            result['protocols'] = proc.stdout[:1000]

        except FileNotFoundError:
            print("[TrafficAnalyzer] tshark not found")
        except Exception as e:
            print(f"[TrafficAnalyzer] Error: {e}")

        return result

    @classmethod
    def extract_files_from_pcap(cls, file_path: str,
                                output_dir: str = './extracted') -> List[str]:
        """从pcap提取文件"""
        extracted = []

        try:
            os.makedirs(output_dir, exist_ok=True)

            cmd = ['tshark', '-r', file_path, '--export-objects', f'http,{output_dir}']
            subprocess.run(cmd, capture_output=True, timeout=120)

            # 列出提取的文件
            for f in os.listdir(output_dir):
                extracted.append(os.path.join(output_dir, f))

        except Exception as e:
            print(f"[TrafficAnalyzer] File extraction error: {e}")

        return extracted


class EncodingConverter:
    """
    编码转换器

    处理各种编码转换
    """

    @classmethod
    def auto_detect(cls, text: str) -> List[str]:
        """自动检测编码类型"""
        detected = []

        # Base64检测
        if re.match(r'^[A-Za-z0-9+/]+=*$', text) and len(text) >= 4:
            detected.append('base64')

        # Hex检测
        if re.match(r'^[0-9a-fA-F]+$', text) and len(text) % 2 == 0:
            detected.append('hex')

        # URL编码检测
        if '%' in text and re.search(r'%[0-9a-fA-F]{2}', text):
            detected.append('url')

        # Unicode检测
        if '\\u' in text or re.search(r'&#\d+;', text):
            detected.append('unicode')

        # Binary检测
        if re.match(r'^[01\s]+$', text):
            detected.append('binary')

        return detected

    @classmethod
    def try_decode(cls, text: str) -> Dict[str, str]:
        """尝试所有可能的解码"""
        results = {}

        # Base64
        try:
            import base64
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            if decoded and decoded.isprintable():
                results['base64'] = decoded
        except Exception:
            pass

        # Hex
        try:
            decoded = bytes.fromhex(text).decode('utf-8', errors='ignore')
            if decoded and decoded.isprintable():
                results['hex'] = decoded
        except Exception:
            pass

        # URL
        try:
            from urllib.parse import unquote
            decoded = unquote(text)
            if decoded != text:
                results['url'] = decoded
        except Exception:
            pass

        # Unicode
        try:
            decoded = text.encode('utf-8').decode('unicode-escape')
            if decoded != text:
                results['unicode'] = decoded
        except Exception:
            pass

        return results