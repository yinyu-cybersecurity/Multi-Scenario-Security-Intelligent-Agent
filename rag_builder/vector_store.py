# rag_builder/vector_store.py - 构建向量库
# 作用：扫描writeups文件夹，建立索引（只需运行一次）

import os
import glob
import hashlib
import frontmatter  # 用于解析YAML头部
from pathlib import Path
from typing import List, Dict
import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

from rag_builder.config import (
    WRITEUPS_DIR, CHROMA_DIR, SUPPORTED_EXTENSIONS,
    EMBEDDING_MODEL, MAX_CONTENT_LENGTH
)


class VectorStoreBuilder:
    """向量库构建器"""

    def __init__(self):
        print("🔨 [RAG] 初始化向量库构建器...")

        # 1. 初始化ChromaDB
        self.client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        self.collection = self.client.get_or_create_collection(
            name="ctf_writeups",
            metadata={"hnsw:space": "cosine"}  # 用余弦相似度
        )

        # 2. 初始化Embedding模型
        print(f"📦 加载模型: {EMBEDDING_MODEL}")
        self.model = SentenceTransformer(EMBEDDING_MODEL)

        print(f"✅ 初始化完成，向量库位置: {CHROMA_DIR}")

    def extract_tags(self, content: str) -> List[str]:
        """从Markdown头部提取tags，兼容两种格式"""
        try:
            # 方法1：标准YAML格式（有 ---）
            try:
                post = frontmatter.loads(content)
                tags = post.get('tags', [])
                if tags:
                    if isinstance(tags, str):
                        return [tags]
                    return tags
            except:
                pass

            # 方法2：你的格式（无 ---，直接 tags: [a, b, c]）
            lines = content.split('\n')
            for line in lines[:5]:  # 只看前5行
                if line.startswith('tags:'):
                    tags_str = line[5:].strip()
                    # 处理 [a, b, c] 格式
                    if tags_str.startswith('[') and tags_str.endswith(']'):
                        tags_content = tags_str[1:-1]
                        tags = [t.strip() for t in tags_content.split(',')]
                        return tags
                    # 处理 a, b, c 格式
                    elif ',' in tags_str:
                        tags = [t.strip() for t in tags_str.split(',')]
                        return tags
                    # 处理单个tag
                    else:
                        return [tags_str]
            return []
        except Exception as e:
            print(f"⚠️ 提取tags失败: {e}")
            return []

    def scan_writeups(self) -> List[Dict]:
        """扫描所有WP文件，提取内容和元数据"""
        print(f"\n📂 扫描目录: {WRITEUPS_DIR}")

        docs = []
        file_count = 0

        # 递归查找所有支持的文件
        for ext in SUPPORTED_EXTENSIONS:
            pattern = f"**/*{ext}"
            files = glob.glob(str(WRITEUPS_DIR / pattern), recursive=True)

            for file_path in tqdm(files, desc=f"处理 {ext} 文件"):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # 提取tags
                    tags = self.extract_tags(content)

                    # 取前MAX_CONTENT_LENGTH字符
                    doc_content = content[:MAX_CONTENT_LENGTH]

                    # 生成唯一ID
                    file_hash = hashlib.md5(file_path.encode()).hexdigest()[:12]

                    docs.append({
                        "id": f"wp_{file_hash}",
                        "content": doc_content,
                        "metadata": {
                            "path": file_path,
                            "filename": os.path.basename(file_path),
                            "tags": tags,
                            "size": len(content)
                        }
                    })
                    file_count += 1

                except Exception as e:
                    print(f"❌ 处理失败 {file_path}: {e}")

        print(f"\n📄 找到 {file_count} 个WP文件")
        return docs

    def build_index(self):
        """构建向量索引"""
        # 1. 扫描文件
        docs = self.scan_writeups()
        if not docs:
            print("⚠️ 没有找到任何WP文件")
            return

        # 2. 准备数据
        documents = [d["content"] for d in docs]
        metadatas = [d["metadata"] for d in docs]
        ids = [d["id"] for d in docs]

        # 3. 计算向量（批量处理）
        print("\n🧠 计算Embedding向量...")
        embeddings = self.model.encode(
            documents,
            batch_size=32,
            show_progress_bar=True
        ).tolist()

        # 4. 存入ChromaDB
        print("💾 存入向量数据库...")

        # 清空现有数据（可选）
        # self.collection.delete(where={})

        # 分批添加（避免内存爆炸）
        batch_size = 100
        for i in tqdm(range(0, len(docs), batch_size), desc="存入数据库"):
            end = min(i + batch_size, len(docs))
            self.collection.add(
                documents=documents[i:end],
                embeddings=embeddings[i:end],
                metadatas=metadatas[i:end],
                ids=ids[i:end]
            )

        print(f"\n✅ 构建完成！入库 {len(docs)} 条记录")
        print(f"📁 向量库位置: {CHROMA_DIR}")
        print(f"📊 总向量数: {self.collection.count()}")


if __name__ == "__main__":
    builder = VectorStoreBuilder()
    builder.build_index()