import math
import time
import string
import random
from collections import Counter

unique_strings = [
    f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=25))}.subdomain{i}.c2.com"
    for i in range(10000)
]

# Algo 1: Original Counter
def entropy_original(data: str) -> float:
    if not data: return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

# Algo 4: Fast set(data) + string.count()
def entropy_set_count(data: str) -> float:
    if not data: return 0.0
    length = len(data)
    entropy = 0.0
    for ch in set(data):
        p = data.count(ch) / length
        entropy -= p * math.log2(p)
    return entropy

def main():
    t0 = time.perf_counter()
    res1 = [entropy_original(s) for s in unique_strings]
    t1 = time.perf_counter()
    dt1 = t1 - t0

    t0 = time.perf_counter()
    res4 = [entropy_set_count(s) for s in unique_strings]
    t1 = time.perf_counter()
    dt4 = t1 - t0

    print(f"1. Original Counter:  {dt1:.4f} s ({dt1*100:.2f} us / string)")
    print(f"4. set() + count():   {dt4:.4f} s ({dt4*100:.2f} us / string) -> {dt1/dt4:.2f}x speedup")
    print(f"Verification: Orig[0]={res1[0]:.4f}, set_count[0]={res4[0]:.4f}")

if __name__ == "__main__":
    main()
