import math
import time
import numpy as np
from collections import Counter
from functools import lru_cache

sample_strings = [
    f"subdomain-{i}.c2tunnel-beacon-domain-randomized-{i%30}.biz"
    for i in range(10000)
]

# Original
def entropy_original(data: str) -> float:
    if not data: return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

# NumPy Vectorized (for unique un-cached strings)
def entropy_numpy(data: str) -> float:
    if not data: return 0.0
    arr = np.frombuffer(data.encode('ascii', 'ignore'), dtype=np.uint8)
    _, counts = np.unique(arr, return_counts=True)
    probs = counts / len(arr)
    return float(-np.sum(probs * np.log2(probs)))

# Fast Math Vectorized
@lru_cache(maxsize=8192)
def entropy_cached_numpy(data: str) -> float:
    if not data: return 0.0
    arr = np.frombuffer(data.encode('ascii', 'ignore'), dtype=np.uint8)
    _, counts = np.unique(arr, return_counts=True)
    probs = counts / len(arr)
    return float(-np.sum(probs * np.log2(probs)))

@lru_cache(maxsize=8192)
def entropy_cached_original(data: str) -> float:
    if not data: return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def benchmark():
    # 1. Original
    t0 = time.perf_counter()
    for s in sample_strings:
        entropy_original(s)
    t1 = time.perf_counter()
    dt_orig = t1 - t0
    us_orig = (dt_orig / len(sample_strings)) * 1e6

    # 2. NumPy
    t0 = time.perf_counter()
    for s in sample_strings:
        entropy_numpy(s)
    t1 = time.perf_counter()
    dt_np = t1 - t0
    us_np = (dt_np / len(sample_strings)) * 1e6

    # 3. Cached NumPy
    t0 = time.perf_counter()
    for s in sample_strings:
        entropy_cached_numpy(s)
    t1 = time.perf_counter()
    dt_cache_np = t1 - t0
    us_cache_np = (dt_cache_np / len(sample_strings)) * 1e6

    # 4. Cached Original
    t0 = time.perf_counter()
    for s in sample_strings:
        entropy_cached_original(s)
    t1 = time.perf_counter()
    dt_cache_orig = t1 - t0
    us_cache_orig = (dt_cache_orig / len(sample_strings)) * 1e6

    print(f"1. Original Counter:   {dt_orig:.4f}s ({us_orig:.2f} us / call)")
    print(f"2. NumPy np.unique:     {dt_np:.4f}s ({us_np:.2f} us / call)")
    print(f"3. Cached NumPy:       {dt_cache_np:.4f}s ({us_cache_np:.2f} us / call)")
    print(f"4. Cached Original:    {dt_cache_orig:.4f}s ({us_cache_orig:.2f} us / call)")

if __name__ == "__main__":
    benchmark()
