# rag_builder/cache.py - RAG Query Result Cache
# Purpose: Cache query results to reduce repeated queries to vector DB during attack planning
# Features: File-based cache with TTL support

import os
import json
import hashlib
import time
from rag_builder.config import SIMILARITY_THRESHOLD
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

# Cache configuration
CACHE_DIR = Path(__file__).parent.parent / "data" / "rag_cache"
CACHE_TTL = 3600  # 1 hour in seconds
CACHE_ENABLED = os.environ.get("RAG_CACHE_ENABLED", "true").lower() == "true"


class RAGCache:
    """
    File-based cache for RAG query results.

    Caches results keyed by (query, sources tuple, top_k) to reduce
    repeated queries to vector DB during attack planning.
    """

    def __init__(self, cache_dir: Path = None, ttl: int = CACHE_TTL):
        """
        Initialize the RAG cache.

        Args:
            cache_dir: Directory to store cache files (default: data/rag_cache)
            ttl: Time-to-live in seconds (default: 3600 = 1 hour)
        """
        self.cache_dir = Path(cache_dir) if cache_dir else CACHE_DIR
        self.ttl = ttl
        self.enabled = CACHE_ENABLED
        self._lock = threading.Lock()

        # Ensure cache directory exists
        if self.enabled:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                print(f"[RAG Cache] Initialized at {self.cache_dir} (TTL: {self.ttl}s)")
            except Exception as e:
                print(f"[RAG Cache] Warning: Failed to create cache directory: {e}")
                self.enabled = False

    def _make_key(self, query: str, sources: Tuple[str, ...], top_k: int) -> str:
        """
        Generate a cache key from query parameters.

        Args:
            query: The search query text
            sources: Tuple of source names to search
            top_k: Number of results to return

        Returns:
            A hash string to use as the cache key
        """
        # Create a unique key from all parameters
        # 包含阈值，确保阈值改变时缓存失效
        key_data = {
            "query": query.strip().lower(),  # Normalize query
            "sources": tuple(sorted(sources)) if sources else (),
            "top_k": top_k,
            "threshold": SIMILARITY_THRESHOLD  # 阈值改变时缓存自动失效
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()

    def _get_cache_path(self, key: str) -> Path:
        """Get the file path for a cache key."""
        return self.cache_dir / f"{key}.json"

    def get(self, query: str, sources: Tuple[str, ...] = None, top_k: int = 5) -> Optional[List[Dict]]:
        """
        Retrieve cached query results if available and not expired.

        Args:
            query: The search query text
            sources: Tuple of source names (e.g., ("writeups", "nuclei"))
            top_k: Number of results requested

        Returns:
            Cached results if available and valid, None otherwise
        """
        if not self.enabled:
            return None

        sources = sources or ()
        key = self._make_key(query, sources, top_k)
        cache_path = self._get_cache_path(key)

        with self._lock:
            try:
                if not cache_path.exists():
                    return None

                with open(cache_path, 'r', encoding='utf-8') as f:
                    cached = json.load(f)

                # Check TTL
                timestamp = cached.get("timestamp", 0)
                if time.time() - timestamp > self.ttl:
                    # Cache expired, remove file
                    try:
                        cache_path.unlink()
                    except:
                        pass
                    return None

                print(f"[RAG Cache] Hit for query: {query[:50]}...")
                return cached.get("results")

            except Exception as e:
                print(f"[RAG Cache] Error reading cache: {e}")
                return None

    def set(self, query: str, results: List[Dict], sources: Tuple[str, ...] = None, top_k: int = 5) -> bool:
        """
        Store query results in cache.

        Args:
            query: The search query text
            results: The query results to cache
            sources: Tuple of source names
            top_k: Number of results

        Returns:
            True if cached successfully, False otherwise
        """
        if not self.enabled:
            return False

        sources = sources or ()
        key = self._make_key(query, sources, top_k)
        cache_path = self._get_cache_path(key)

        with self._lock:
            try:
                cached = {
                    "query": query,
                    "sources": list(sources),
                    "top_k": top_k,
                    "timestamp": time.time(),
                    "results": results
                }

                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump(cached, f, ensure_ascii=False, indent=2)

                print(f"[RAG Cache] Stored result for query: {query[:50]}...")
                return True

            except Exception as e:
                print(f"[RAG Cache] Error writing cache: {e}")
                return False

    def clear(self) -> int:
        """
        Clear all cached results.

        Returns:
            Number of cache files removed
        """
        count = 0
        with self._lock:
            try:
                for cache_file in self.cache_dir.glob("*.json"):
                    try:
                        cache_file.unlink()
                        count += 1
                    except:
                        pass
                print(f"[RAG Cache] Cleared {count} cache files")
            except Exception as e:
                print(f"[RAG Cache] Error clearing cache: {e}")

        return count

    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries.

        Returns:
            Number of expired entries removed
        """
        count = 0
        with self._lock:
            try:
                current_time = time.time()
                for cache_file in self.cache_dir.glob("*.json"):
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            cached = json.load(f)

                        timestamp = cached.get("timestamp", 0)
                        if current_time - timestamp > self.ttl:
                            cache_file.unlink()
                            count += 1
                    except:
                        # If we can't read it, remove it
                        try:
                            cache_file.unlink()
                            count += 1
                        except:
                            pass

                if count > 0:
                    print(f"[RAG Cache] Cleaned up {count} expired entries")
            except Exception as e:
                print(f"[RAG Cache] Error during cleanup: {e}")

        return count

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dict with cache statistics
        """
        stats = {
            "enabled": self.enabled,
            "cache_dir": str(self.cache_dir),
            "ttl": self.ttl,
            "total_entries": 0,
            "total_size_bytes": 0,
            "expired_entries": 0
        }

        if not self.enabled:
            return stats

        try:
            current_time = time.time()
            for cache_file in self.cache_dir.glob("*.json"):
                stats["total_entries"] += 1
                stats["total_size_bytes"] += cache_file.stat().st_size

                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cached = json.load(f)
                    timestamp = cached.get("timestamp", 0)
                    if current_time - timestamp > self.ttl:
                        stats["expired_entries"] += 1
                except:
                    pass

            stats["total_size_mb"] = round(stats["total_size_bytes"] / (1024 * 1024), 2)

        except Exception as e:
            print(f"[RAG Cache] Error getting stats: {e}")

        return stats


# Global singleton instance
_cache_instance: Optional[RAGCache] = None
_cache_lock = threading.Lock()


def get_cache() -> RAGCache:
    """
    Get the global cache instance (singleton pattern).

    Returns:
        RAGCache instance
    """
    global _cache_instance

    if _cache_instance is None:
        with _cache_lock:
            if _cache_instance is None:
                _cache_instance = RAGCache()

    return _cache_instance


def reset_cache():
    """Reset the cache singleton (for testing)."""
    global _cache_instance
    with _cache_lock:
        _cache_instance = None


# Simple test
if __name__ == "__main__":
    cache = RAGCache()

    # Test basic operations
    print("\n--- Testing RAG Cache ---")
    print(f"Cache stats: {cache.get_stats()}")

    # Test set/get
    test_query = "SQL injection attack"
    test_results = [
        {"id": "test_1", "content": "SQL injection payload...", "similarity": 0.95},
        {"id": "test_2", "content": "Union select...", "similarity": 0.85}
    ]

    print(f"\nSetting cache for query: {test_query}")
    cache.set(test_query, test_results, sources=("writeups", "nuclei"), top_k=5)

    print(f"Getting cache for query: {test_query}")
    cached = cache.get(test_query, sources=("writeups", "nuclei"), top_k=5)
    print(f"Cached result: {cached}")

    print(f"\nCache stats after operations: {cache.get_stats()}")

    # Test TTL expiration (simulate by setting short TTL)
    short_cache = RAGCache(ttl=1)
    short_cache.set("quick test", test_results)
    print(f"\nShort TTL cache hit: {short_cache.get('quick test')}")
    time.sleep(2)
    print(f"Short TTL cache after 2s: {short_cache.get('quick test')}")

    # Cleanup
    cache.clear()
    print("\n--- Cache test complete ---")