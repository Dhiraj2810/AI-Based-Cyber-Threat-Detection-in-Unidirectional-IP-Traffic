import os
import sys
sys.path.insert(0, "d:/PS SIH26145")
import time
from backend.benchmark.throughput_benchmark import run_throughput_benchmark

def main():
    print("=" * 70)
    print("TESTING IMPACT OF BATCH SIZE & PARAMETERS ON BASELINE THROUGHPUT")
    print("=" * 70)

    batch_sizes = [20, 50, 100, 200, 500, 1000]

    for bs in batch_sizes:
        report = run_throughput_benchmark(num_flows=10000, use_live_state=False, batch_size=bs)
        fps = report.get("flows_per_second", 0.0)
        exec_t = report.get("execution_time_seconds", 0.0)
        print(f"Batch Size: {bs:<5} -> Throughput: {fps:<10.2f} flows/sec | Exec Time: {exec_t:.4f}s")

if __name__ == "__main__":
    main()
