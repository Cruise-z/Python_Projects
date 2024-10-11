from datasets import load_dataset

# 清理缓存
from datasets import set_caching_enabled, cleanup_cache_files

# 打印删除的缓存大小
deleted_size = cleanup_cache_files()
print(f"Deleted cache size: {deleted_size} bytes")
