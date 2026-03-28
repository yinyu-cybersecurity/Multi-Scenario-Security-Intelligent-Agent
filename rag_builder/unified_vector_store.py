# rag_builder/unified_vector_store.py - 统一向量库构建器
# 作用：整合Writeups、Nuclei模板、Payload知识库，建立向量索引

import os
import glob
import hashlib
import yaml
import re
from pathlib import Path
from typing import List, Dict, Optional
import chromadb
from tqdm import tqdm

# 重要：先导入config设置HF_ENDPOINT环境变量，再导入sentence_transformers
# 这样模型加载时会使用国内镜像而不是原始huggingface.co
from rag_builder.config import (
    WRITEUPS_DIR, CHROMA_DIR, SUPPORTED_EXTENSIONS,
    EMBEDDING_MODEL, MAX_CONTENT_LENGTH, HF_ENDPOINT
)

# config.py已设置HF_ENDPOINT，现在可以安全导入SentenceTransformer
from sentence_transformers import SentenceTransformer

# 新增知识库目录
KNOWLEDGE_BASE_DIR = Path(__file__).parent.parent / "data" / "knowledge_base"
SECURITY_RESOURCES_DIR = Path(__file__).parent.parent / "data" / "security_resources"
NUCLEI_TEMPLATES_DIR = Path(__file__).parent.parent / "data" / "nuclei_templates"


class UnifiedVectorStoreBuilder:
    """统一向量库构建器 - 整合多种知识源"""

    def __init__(self, embedding_model: str = None):
        print("[RAG] Initializing unified vector store builder...")

        # 使用指定的模型或默认模型
        model_name = embedding_model or EMBEDDING_MODEL

        # 1. 初始化ChromaDB
        self.client = chromadb.PersistentClient(path=str(CHROMA_DIR))

        # 创建多个collection分别存储不同类型的知识
        self.writeups_collection = self.client.get_or_create_collection(
            name="ctf_writeups",
            metadata={"hnsw:space": "cosine", "type": "writeups"}
        )

        self.nuclei_collection = self.client.get_or_create_collection(
            name="nuclei_templates",
            metadata={"hnsw:space": "cosine", "type": "templates"}
        )

        self.payloads_collection = self.client.get_or_create_collection(
            name="payloads",
            metadata={"hnsw:space": "cosine", "type": "payloads"}
        )

        self.security_resources_collection = self.client.get_or_create_collection(
            name="security_resources",
            metadata={"hnsw:space": "cosine", "type": "security_resources"}
        )

        # 2. 初始化Embedding模型
        print(f"[RAG] Loading model: {model_name}")
        self.model = SentenceTransformer(model_name)

        print(f"[RAG] Initialization complete")
        print(f"   - Writeups Collection: {self.writeups_collection.count()} records")
        print(f"   - Nuclei Collection: {self.nuclei_collection.count()} records")
        print(f"   - Payloads Collection: {self.payloads_collection.count()} records")
        print(f"   - Security Resources Collection: {self.security_resources_collection.count()} records")

    def extract_yaml_rag_annotation(self, content: str) -> Optional[Dict]:
        """从Nuclei YAML模板提取RAG Annotation"""
        try:
            # 查找RAG Annotation注释块
            rag_pattern = r'# RAG Annotation:\s*\n((?:# [^\n]+\n)*)'
            match = re.search(rag_pattern, content)

            if not match:
                return None

            annotation_block = match.group(1)
            result = {}

            for line in annotation_block.split('\n'):
                if line.startswith('# '):
                    parts = line[2:].split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        result[key] = value

            return result if result else None
        except Exception as e:
            return None

    def scan_writeups(self) -> List[Dict]:
        """扫描CTF Writeups文件"""
        print(f"\n[RAG] Scanning Writeups directory: {WRITEUPS_DIR}")

        docs = []
        file_count = 0

        for ext in SUPPORTED_EXTENSIONS:
            pattern = f"**/*{ext}"
            files = glob.glob(str(WRITEUPS_DIR / pattern), recursive=True)

            for file_path in tqdm(files, desc=f"Processing Writeup {ext} files"):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # 提取tags
                    tags = self._extract_tags(content)
                    # ChromaDB不接受空列表，转换为字符串
                    tags_str = ','.join(tags) if tags else ''

                    # 取前MAX_CONTENT_LENGTH字符
                    doc_content = content[:MAX_CONTENT_LENGTH]

                    # 生成唯一ID
                    file_hash = hashlib.md5(file_path.encode()).hexdigest()[:12]

                    # 构建metadata（ChromaDB要求值不为空列表）
                    metadata = {
                        "path": file_path,
                        "filename": os.path.basename(file_path),
                        "type": "writeup",
                        "size": len(content)
                    }
                    if tags_str:
                        metadata["tags"] = tags_str

                    docs.append({
                        "id": f"wp_{file_hash}",
                        "content": doc_content,
                        "metadata": metadata
                    })
                    file_count += 1

                except Exception as e:
                    print(f"[RAG] Error processing {file_path}: {e}")

        print(f"[RAG] Found {file_count} Writeup files")
        return docs

    def scan_nuclei_templates(self) -> List[Dict]:
        """扫描Nuclei模板（优先处理已标注的）"""
        print(f"\n[RAG] Scanning Nuclei templates directory: {NUCLEI_TEMPLATES_DIR}")

        docs = []
        file_count = 0
        annotated_count = 0

        # 扫描所有YAML文件
        yaml_files = glob.glob(str(NUCLEI_TEMPLATES_DIR / "**/*.yaml"), recursive=True)

        for file_path in tqdm(yaml_files, desc="Processing Nuclei YAML"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # 提取RAG Annotation
                rag_annotation = self.extract_yaml_rag_annotation(content)

                # 构建文档内容（用于检索）
                if rag_annotation:
                    # 使用RAG Annotation作为主要检索内容
                    search_content = f"""
Vulnerability Name: {rag_annotation.get('name', 'Unknown')}
Description: {rag_annotation.get('description', '')}
Vulnerability Type: {rag_annotation.get('vuln_type', '')}
Severity: {rag_annotation.get('severity', '')}
CVE ID: {rag_annotation.get('cve_id', '')}
Template Path: {file_path}
"""
                    annotated_count += 1
                else:
                    # 没有标注的模板，解析YAML提取关键信息
                    try:
                        yaml_data = yaml.safe_load(content)
                        info = yaml_data.get('info', {})
                        tags_list = info.get('tags', [])
                        tags_str = ','.join(tags_list) if tags_list else ''
                        search_content = f"""
Vulnerability Name: {info.get('name', 'Unknown')}
Description: {info.get('description', '')}
Severity: {info.get('severity', 'unknown')}
Tags: {tags_str}
Template Path: {file_path}
"""
                    except:
                        # 解析失败，取前500字符
                        search_content = content[:500]

                # 生成唯一ID
                file_hash = hashlib.md5(file_path.encode()).hexdigest()[:12]

                # 从路径推断分类
                rel_path = os.path.relpath(file_path, NUCLEI_TEMPLATES_DIR)
                category = rel_path.split(os.sep)[0] if os.sep in rel_path else "other"

                # 构建metadata（确保没有空列表）
                metadata = {
                    "path": file_path,
                    "filename": os.path.basename(file_path),
                    "category": category,
                    "type": "nuclei_template",
                    "has_annotation": str(bool(rag_annotation)),
                    "size": len(content)
                }
                # 只有非空值才添加
                if rag_annotation:
                    if rag_annotation.get('name'):
                        metadata["name"] = rag_annotation.get('name')
                    if rag_annotation.get('vuln_type'):
                        metadata["vuln_type"] = rag_annotation.get('vuln_type')
                    if rag_annotation.get('severity'):
                        metadata["severity"] = rag_annotation.get('severity')
                    if rag_annotation.get('cve_id'):
                        metadata["cve_id"] = rag_annotation.get('cve_id')

                docs.append({
                    "id": f"nuclei_{file_hash}",
                    "content": search_content[:MAX_CONTENT_LENGTH],
                    "metadata": metadata
                })
                file_count += 1

            except Exception as e:
                print(f"[RAG] Error processing {file_path}: {e}")

        print(f"[RAG] Found {file_count} Nuclei templates (annotated: {annotated_count})")
        return docs

    def scan_payloads(self) -> List[Dict]:
        """扫描Payload知识库"""
        print(f"\n[RAG] Scanning Payload knowledge base: {KNOWLEDGE_BASE_DIR}")

        docs = []
        file_count = 0

        if not KNOWLEDGE_BASE_DIR.exists():
            print("[RAG] Payload knowledge base directory not found")
            return docs

        md_files = glob.glob(str(KNOWLEDGE_BASE_DIR / "*.md"), recursive=False)

        for file_path in tqdm(md_files, desc="Processing Payload files"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # 从文件名推断漏洞类型
                filename = os.path.basename(file_path)
                vuln_type = filename.replace('payload_', '').replace('.md', '').replace('_', ' ')

                # 提取标题和关键内容
                lines = content.split('\n')
                title = lines[0] if lines else vuln_type

                # 构建检索内容
                search_content = f"""
Payload Type: {vuln_type}
Title: {title}
Content Summary: {content[:1500]}
"""

                file_hash = hashlib.md5(file_path.encode()).hexdigest()[:12]

                docs.append({
                    "id": f"payload_{file_hash}",
                    "content": search_content[:MAX_CONTENT_LENGTH],
                    "metadata": {
                        "path": file_path,
                        "filename": filename,
                        "vuln_type": vuln_type,
                        "type": "payload",
                        "size": len(content)
                    }
                })
                file_count += 1

            except Exception as e:
                print(f"[RAG] Error processing {file_path}: {e}")

        print(f"[RAG] Found {file_count} Payload files")
        return docs

    def scan_security_resources(self) -> List[Dict]:
        """扫描Security Resources知识库 (PayloadsAllTheThings + SecLists)"""
        print(f"\n[RAG] Scanning Security Resources directory: {SECURITY_RESOURCES_DIR}")

        docs = []
        file_count = 0

        if not SECURITY_RESOURCES_DIR.exists():
            print("[RAG] Security resources directory not found")
            return docs

        # 扫描 PayloadsAllTheThings - 重点处理README和关键文档
        patt_path = SECURITY_RESOURCES_DIR / "PayloadsAllTheThings-4.2"
        if patt_path.exists():
            print("[RAG] Processing PayloadsAllTheThings...")
            # 只处理README.md和关键漏洞类型目录下的README
            for md_file in glob.glob(str(patt_path / "**/README.md"), recursive=True):
                try:
                    with open(md_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    rel_path = os.path.relpath(md_file, patt_path)
                    vuln_category = rel_path.split(os.sep)[0] if os.sep in rel_path else "general"

                    # 构建检索内容
                    search_content = f"""
Category: {vuln_category}
Source: PayloadsAllTheThings
Content: {content[:1500]}
"""

                    file_hash = hashlib.md5(md_file.encode()).hexdigest()[:12]

                    docs.append({
                        "id": f"sec_patt_{file_hash}",
                        "content": search_content[:MAX_CONTENT_LENGTH],
                        "metadata": {
                            "path": md_file,
                            "source": "PayloadsAllTheThings",
                            "category": vuln_category,
                            "type": "security_resource",
                            "size": len(content)
                        }
                    })
                    file_count += 1
                except Exception as e:
                    pass

        # 扫描 SecLists - 重点处理字典描述和关键文件
        seclists_path = SECURITY_RESOURCES_DIR / "SecLists-master"
        if seclists_path.exists():
            print("[RAG] Processing SecLists...")
            # 处理关键字典文件（限制大小）
            important_patterns = [
                "**/Passwords/*.txt",
                "**/Usernames/*.txt",
                "**/Discovery/*.txt"
            ]
            for pattern in important_patterns:
                for txt_file in glob.glob(str(seclists_path / pattern), recursive=True)[:50]:  # 限制每个类别50个
                    try:
                        # 只读取前100行作为样本
                        with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = [f.readline() for _ in range(100)]
                            content = ''.join(lines)

                        rel_path = os.path.relpath(txt_file, seclists_path)
                        dict_type = rel_path.split(os.sep)[0] if os.sep in rel_path else "other"

                        # 构建检索内容
                        search_content = f"""
Dictionary Type: {dict_type}
Source: SecLists
File: {os.path.basename(txt_file)}
Sample Entries: {content[:1000]}
"""

                        file_hash = hashlib.md5(txt_file.encode()).hexdigest()[:12]

                        docs.append({
                            "id": f"sec_sl_{file_hash}",
                            "content": search_content[:MAX_CONTENT_LENGTH],
                            "metadata": {
                                "path": txt_file,
                                "source": "SecLists",
                                "dict_type": dict_type,
                                "type": "security_resource",
                                "size": len(content)
                            }
                        })
                        file_count += 1
                    except Exception as e:
                        pass

        print(f"[RAG] Found {file_count} Security Resource files")
        return docs

    def _extract_tags(self, content: str) -> List[str]:
        """从Markdown头部提取tags"""
        try:
            # 方法1：标准YAML格式（有 ---）
            try:
                import frontmatter
                post = frontmatter.loads(content)
                tags = post.get('tags', [])
                if tags:
                    if isinstance(tags, str):
                        return [tags]
                    return tags
            except:
                pass

            # 方法2：无 --- 格式
            lines = content.split('\n')
            for line in lines[:5]:
                if line.startswith('tags:'):
                    tags_str = line[5:].strip()
                    if tags_str.startswith('[') and tags_str.endswith(']'):
                        tags_content = tags_str[1:-1]
                        return [t.strip() for t in tags_content.split(',')]
                    elif ',' in tags_str:
                        return [t.strip() for t in tags_str.split(',')]
                    else:
                        return [tags_str]
            return []
        except:
            return []

    def build_all_indices(self, clear_existing: bool = False):
        """构建所有向量索引"""
        print("\n" + "="*60)
        print("[RAG] Starting unified vector knowledge base construction")
        print("="*60)

        # 1. 处理Writeups
        writeups = self.scan_writeups()
        if writeups:
            self._add_to_collection(self.writeups_collection, writeups, "writeups", clear_existing)

        # 2. 处理Nuclei模板
        nuclei = self.scan_nuclei_templates()
        if nuclei:
            self._add_to_collection(self.nuclei_collection, nuclei, "nuclei", clear_existing)

        # 3. 处理Payloads
        payloads = self.scan_payloads()
        if payloads:
            self._add_to_collection(self.payloads_collection, payloads, "payloads", clear_existing)

        # 4. 处理Security Resources
        security_resources = self.scan_security_resources()
        if security_resources:
            self._add_to_collection(self.security_resources_collection, security_resources, "security_resources", clear_existing)

        print("\n" + "="*60)
        print("[RAG] Vector knowledge base construction complete!")
        print("="*60)
        print(f"[RAG] Statistics:")
        print(f"   - Writeups: {self.writeups_collection.count()} records")
        print(f"   - Nuclei templates: {self.nuclei_collection.count()} records")
        print(f"   - Payloads: {self.payloads_collection.count()} records")
        print(f"   - Security Resources: {self.security_resources_collection.count()} records")
        total = (self.writeups_collection.count() + self.nuclei_collection.count() +
                 self.payloads_collection.count() + self.security_resources_collection.count())
        print(f"   - Total: {total} records")
        print(f"[RAG] Vector store location: {CHROMA_DIR}")

    def _add_to_collection(self, collection, docs: List[Dict], name: str, clear: bool):
        """将文档添加到指定collection"""
        if clear:
            try:
                # 清空现有数据
                existing_ids = collection.get()['ids']
                if existing_ids:
                    collection.delete(ids=existing_ids)
                print(f"[RAG] Cleared {name} collection")
            except Exception as e:
                print(f"[RAG] Clear failed: {e}")

        if not docs:
            print(f"[RAG] No documents to add for {name}")
            return

        documents = [d["content"] for d in docs]
        metadatas = [d["metadata"] for d in docs]
        ids = [d["id"] for d in docs]

        # 计算向量
        print(f"\n[RAG] Computing {name} embedding vectors...")
        embeddings = self.model.encode(
            documents,
            batch_size=32,
            show_progress_bar=True
        ).tolist()

        # 分批添加
        batch_size = 100
        print(f"[RAG] Storing {name} to vector database...")
        for i in tqdm(range(0, len(docs), batch_size), desc=f"Adding to {name}"):
            end = min(i + batch_size, len(docs))
            collection.add(
                documents=documents[i:end],
                embeddings=embeddings[i:end],
                metadatas=metadatas[i:end],
                ids=ids[i:end]
            )

        print(f"[RAG] Added {len(docs)} documents to {name} collection")


class UnifiedRetriever:
    """统一检索器 - 支持跨collection检索"""

    def __init__(self):
        print("[RAG] Initializing unified retriever...")

        self.client = chromadb.PersistentClient(path=str(CHROMA_DIR))

        # 获取所有collections
        try:
            self.writeups_collection = self.client.get_collection("ctf_writeups")
        except:
            self.writeups_collection = None

        try:
            self.nuclei_collection = self.client.get_collection("nuclei_templates")
        except:
            self.nuclei_collection = None

        try:
            self.payloads_collection = self.client.get_collection("payloads")
        except:
            self.payloads_collection = None

        try:
            self.security_resources_collection = self.client.get_collection("security_resources")
        except:
            self.security_resources_collection = None

        # 加载模型
        self.model = SentenceTransformer(EMBEDDING_MODEL)

        # 统计
        total = 0
        if self.writeups_collection:
            total += self.writeups_collection.count()
        if self.nuclei_collection:
            total += self.nuclei_collection.count()
        if self.payloads_collection:
            total += self.payloads_collection.count()
        if self.security_resources_collection:
            total += self.security_resources_collection.count()

        print(f"[RAG] Retriever ready, knowledge base contains {total} records")

    def search(self, query: str, top_k: int = 5, sources: List[str] = None) -> Dict:
        """
        统一检索接口

        Args:
            query: 查询文本
            top_k: 每个来源返回的数量
            sources: 指定检索来源 ["writeups", "nuclei", "payloads", "security_resources"]

        Returns:
            {
                "writeups": [...],
                "nuclei": [...],
                "payloads": [...],
                "security_resources": [...],
                "total": N
            }
        """
        sources = sources or ["writeups", "nuclei", "payloads", "security_resources"]
        query_embedding = self.model.encode(query).tolist()

        results = {"total": 0}

        # 检索Writeups
        if "writeups" in sources and self.writeups_collection:
            wp_results = self._search_collection(self.writeups_collection, query_embedding, top_k)
            results["writeups"] = wp_results
            results["total"] += len(wp_results)

        # 检索Nuclei模板
        if "nuclei" in sources and self.nuclei_collection:
            nuclei_results = self._search_collection(self.nuclei_collection, query_embedding, top_k)
            results["nuclei"] = nuclei_results
            results["total"] += len(nuclei_results)

        # 检索Payloads
        if "payloads" in sources and self.payloads_collection:
            payload_results = self._search_collection(self.payloads_collection, query_embedding, top_k)
            results["payloads"] = payload_results
            results["total"] += len(payload_results)

        # 检索Security Resources
        if "security_resources" in sources and self.security_resources_collection:
            sec_results = self._search_collection(self.security_resources_collection, query_embedding, top_k)
            results["security_resources"] = sec_results
            results["total"] += len(sec_results)

        return results

    def _search_collection(self, collection, embedding: List, top_k: int) -> List[Dict]:
        """在指定collection中检索"""
        try:
            results = collection.query(
                query_embeddings=[embedding],
                n_results=top_k,
                include=["documents", "metadatas", "distances"]
            )

            formatted = []
            if results['ids'][0]:
                for i in range(len(results['ids'][0])):
                    distance = results['distances'][0][i]
                    similarity = 1 - distance

                    formatted.append({
                        "id": results['ids'][0][i],
                        "content": results['documents'][0][i],
                        "metadata": results['metadatas'][0][i],
                        "similarity": round(similarity, 3)
                    })

            return formatted
        except Exception as e:
            print(f"[RAG] Search failed: {e}")
            return []

    def search_by_vuln_type(self, vuln_type: str, top_k: int = 10) -> Dict:
        """按漏洞类型检索相关内容"""
        query = f"vulnerability type: {vuln_type}"
        return self.search(query, top_k)

    def search_by_cve(self, cve_id: str) -> Dict:
        """按CVE编号检索"""
        query = f"CVE ID: {cve_id}"
        return self.search(query, top_k=3)


# 全局单例
_unified_retriever = None
_retriever_init_error = None

def get_unified_retriever() -> UnifiedRetriever:
    """获取统一检索器实例

    改进：支持初始化失败后重试，而不是永久返回失败状态
    """
    global _unified_retriever, _retriever_init_error

    if _unified_retriever is not None:
        return _unified_retriever

    # 如果之前有错误，打印警告但允许重试（可能是临时网络问题）
    if _retriever_init_error:
        print(f"[RAG] Warning: Previous initialization failed: {_retriever_init_error}")
        print("[RAG] Attempting re-initialization...")

    try:
        _unified_retriever = UnifiedRetriever()
        _retriever_init_error = None  # 清除错误记录
        return _unified_retriever
    except Exception as e:
        _retriever_init_error = str(e)
        print(f"[RAG] Error initializing retriever: {e}")
        # 返回一个空实例，避免API崩溃
        raise  # 让调用者处理异常


def reset_retriever():
    """重置检索器单例（用于测试或强制重新初始化）"""
    global _unified_retriever, _retriever_init_error
    _unified_retriever = None
    _retriever_init_error = None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build unified vector knowledge base")
    parser.add_argument("--clear", action="store_true", help="Clear existing data")
    parser.add_argument("--model", default=None, help="Specify embedding model")
    args = parser.parse_args()

    builder = UnifiedVectorStoreBuilder(embedding_model=args.model)
    builder.build_all_indices(clear_existing=args.clear)