"""
Performance tests for hash functions (SHA-256 and SHA3-256).
Shows real throughput numbers for different data sizes.
"""

import time
import statistics
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import hash modules
from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256
from src.utils.csprng import generate_random_bytes


def generate_test_data(size_bytes):
    """Generate test data of specified size"""
    return generate_random_bytes(size_bytes)


def benchmark_hash_function(hash_class, data_size=1048576, iterations=10, warmup=5):
    """
    Benchmark hash function with detailed metrics

    Returns dictionary with performance metrics
    """
    # Generate test data
    data = generate_test_data(data_size)

    # Warm-up
    for _ in range(warmup):
        hasher = hash_class()
        hasher.update(data)
        _ = hasher.hexdigest()

    # Benchmark update() + digest()
    update_digest_times = []
    for _ in range(iterations):
        hasher = hash_class()
        start = time.perf_counter()
        hasher.update(data)
        result = hasher.hexdigest()
        update_digest_times.append(time.perf_counter() - start)

    # Benchmark hash() method
    hash_method_times = []
    for _ in range(iterations):
        hasher = hash_class()
        start = time.perf_counter()
        result = hasher.hash(data)
        hash_method_times.append(time.perf_counter() - start)

    # Calculate metrics
    update_mean = statistics.mean(update_digest_times)
    update_std = statistics.stdev(update_digest_times) if len(update_digest_times) > 1 else 0
    hash_mean = statistics.mean(hash_method_times)
    hash_std = statistics.stdev(hash_method_times) if len(hash_method_times) > 1 else 0

    # Calculate throughput (MB/s)
    data_mb = data_size / (1024 * 1024)
    update_throughput = data_mb / update_mean if update_mean > 0 else 0
    hash_throughput = data_mb / hash_mean if hash_mean > 0 else 0

    return {
        'hash_function': hash_class.__name__,
        'data_size_bytes': data_size,
        'data_size_mb': round(data_mb, 3),
        'iterations': iterations,

        # update() + digest() metrics
        'update_digest_time_mean': round(update_mean, 4),
        'update_digest_time_std': round(update_std, 4),
        'update_digest_throughput': round(update_throughput, 2),
        'update_digest_speed': f"{update_throughput:.2f} MB/s",

        # hash() method metrics
        'hash_method_time_mean': round(hash_mean, 4),
        'hash_method_time_std': round(hash_std, 4),
        'hash_method_throughput': round(hash_throughput, 2),
        'hash_method_speed': f"{hash_throughput:.2f} MB/s",

        # Overall
        'operations_per_second': round(1 / min(update_mean, hash_mean), 1),
        'recommended_method': 'hash()' if hash_mean < update_mean else 'update()+digest()',
    }


def run_hash_throughput_comparison():
    """Compare throughput of hash functions for different data sizes"""
    print("=" * 100)
    print("HASH FUNCTION THROUGHPUT COMPARISON (Higher is Better)")
    print("=" * 100)

    hash_functions = [
        (SHA256, "SHA-256"),
        (SHA3_256, "SHA3-256"),
    ]

    data_sizes = [
        16,        # Tiny
        64,        # Small
        256,       # Medium small
        1024,      # 1 KB
        16384,     # 16 KB
        65536,     # 64 KB
        262144,    # 256 KB
        1048576,   # 1 MB (максимум по требованиям)
    ]

    print(f"\n{'Hash':<10} {'Data Size':<12} {'hash() (MB/s)':<15} {'update+digest() (MB/s)':<20} {'Best Method':<12}")
    print("-" * 100)

    results_by_hash = {}

    for hash_class, hash_name in hash_functions:
        results_by_hash[hash_name] = []

        for data_size in data_sizes:
            try:
                result = benchmark_hash_function(hash_class, data_size, iterations=5, warmup=3)
                results_by_hash[hash_name].append(result)

                # Format data size
                if data_size < 1024:
                    size_str = f"{data_size}B"
                elif data_size < 1024*1024:
                    size_str = f"{data_size//1024}KB"
                else:
                    size_str = f"{data_size//(1024*1024)}MB"

                print(f"{hash_name:<10} {size_str:<12} {result['hash_method_throughput']:>8.2f} MB/s   "
                      f"{result['update_digest_throughput']:>8.2f} MB/s         "
                      f"{result['recommended_method']:<12}")

            except Exception as e:
                print(f"{hash_name:<10} {size_str:<12} {'ERROR':<15} {str(e)[:30]:<20}")

    return results_by_hash


def benchmark_small_data_performance():
    """Benchmark hash functions with small data (common use case)"""
    print("\n" + "=" * 100)
    print("SMALL DATA HASHING PERFORMANCE (Typical Use Cases)")
    print("=" * 100)

    hash_functions = [
        (SHA256, "SHA-256"),
        (SHA3_256, "SHA3-256"),
    ]

    small_data_sizes = [1, 8, 16, 32, 64, 128, 256, 512, 1024]
    iterations = 1000

    print(f"\n{'Hash':<10} {'Data Size':<12} {'Operations/sec':<15} {'Time per op (μs)':<16}")
    print("-" * 100)

    results = {}

    for hash_class, hash_name in hash_functions:
        results[hash_name] = []
        print()

        for data_size in small_data_sizes:
            data = generate_test_data(data_size)

            # Time many operations
            start = time.perf_counter()
            for _ in range(iterations):
                hasher = hash_class()
                hasher.update(data)
                _ = hasher.hexdigest()
            total_time = time.perf_counter() - start

            # Calculate metrics
            ops_per_sec = iterations / total_time if total_time > 0 else 0
            time_per_op = (total_time / iterations) * 1_000_000  # microseconds

            results[hash_name].append({
                'data_size': data_size,
                'ops_per_sec': ops_per_sec,
                'time_per_op_us': time_per_op
            })

            print(f"{hash_name:<10} {data_size:<12} {ops_per_sec:>10,.0f}     {time_per_op:>10.2f} μs")

    return results


def run_streaming_hash_performance():
    """Test hash performance with streaming/chunked data"""
    print("\n" + "=" * 100)
    print("STREAMING HASH PERFORMANCE (10MB total, different chunk sizes)")
    print("=" * 100)

    hash_functions = [
        (SHA256, "SHA-256"),
        (SHA3_256, "SHA3-256"),
    ]

    total_size = 10 * 1024 * 1024  # 10 MB
    chunk_sizes = [1024, 8192, 65536, 262144]  # 1KB, 8KB, 64KB, 256KB

    print(f"\n{'Hash':<10} {'Chunk Size':<12} {'Throughput (MB/s)':<16} {'Total Time (s)':<14}")
    print("-" * 100)

    results = {}

    for hash_class, hash_name in hash_functions:
        results[hash_name] = []
        print()

        for chunk_size in chunk_sizes:
            # Generate data in chunks
            hasher = hash_class()

            start = time.perf_counter()

            remaining = total_size
            while remaining > 0:
                current_chunk = min(chunk_size, remaining)
                data = generate_test_data(current_chunk)
                hasher.update(data)
                remaining -= current_chunk

            digest = hasher.hexdigest()
            total_time = time.perf_counter() - start

            throughput = (total_size / (1024 * 1024)) / total_time

            results[hash_name].append({
                'chunk_size': chunk_size,
                'throughput': throughput,
                'total_time': total_time,
                'digest': digest[:16] + "..."
            })

            chunk_str = f"{chunk_size//1024}KB" if chunk_size < 1024*1024 else f"{chunk_size//(1024*1024)}MB"
            print(f"{hash_name:<10} {chunk_str:<12} {throughput:>10.2f} MB/s   {total_time:>10.4f}")

    return results


def compare_hash_function_overhead():
    """Compare overhead of hash function initialization"""
    print("\n" + "=" * 100)
    print("HASH FUNCTION OVERHEAD COMPARISON")
    print("=" * 100)

    hash_functions = [
        (SHA256, "SHA-256"),
        (SHA3_256, "SHA3-256"),
    ]

    iterations = 10000

    print(f"\n{'Hash':<10} {'Init Time (μs)':<16} {'Init+Hash 1B (μs)':<18} {'Overhead %':<12}")
    print("-" * 100)

    results = {}

    for hash_class, hash_name in hash_functions:
        # Measure initialization time
        init_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            hasher = hash_class()
            init_times.append(time.perf_counter() - start)

        # Measure initialization + hashing 1 byte
        full_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            hasher = hash_class()
            hasher.update(b"x")
            _ = hasher.hexdigest()
            full_times.append(time.perf_counter() - start)

        init_mean = statistics.mean(init_times) * 1_000_000  # microseconds
        full_mean = statistics.mean(full_times) * 1_000_000  # microseconds
        overhead_percent = (init_mean / full_mean) * 100 if full_mean > 0 else 0

        results[hash_name] = {
            'init_time_us': init_mean,
            'full_time_us': full_mean,
            'overhead_percent': overhead_percent
        }

        print(f"{hash_name:<10} {init_mean:>10.2f} μs    {full_mean:>10.2f} μs      {overhead_percent:>8.1f}%")

    return results


def generate_hash_performance_report():
    """Generate comprehensive hash performance report"""
    print("\n" + "=" * 100)
    print("CRYPTOCORE HASH FUNCTION PERFORMANCE REPORT")
    print("=" * 100)
    print(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python: {sys.version}")
    print()

    # Run all benchmarks
    print("1. Throughput Comparison by Data Size:")
    throughput_results = run_hash_throughput_comparison()

    print("\n2. Small Data Performance:")
    small_data_results = benchmark_small_data_performance()

    print("\n3. Streaming Performance (10MB):")
    streaming_results = run_streaming_hash_performance()

    print("\n4. Function Overhead:")
    overhead_results = compare_hash_function_overhead()

    # Summary
    print("\n" + "=" * 100)
    print("PERFORMANCE SUMMARY")
    print("=" * 100)

    # Calculate average performance for 1MB data
    for hash_name in ['SHA-256', 'SHA3-256']:
        if hash_name in throughput_results:
            hash_results = [r for r in throughput_results[hash_name] if r['data_size_bytes'] == 1048576]
            if hash_results:
                result = hash_results[0]
                print(f"\n{hash_name}:")
                print(f"  - Best method: {result['recommended_method']}")
                print(f"  - Throughput: {result['hash_method_throughput']} MB/s")
                print(f"  - 1MB hash time: {result['hash_method_time_mean']:.3f}s")

    # Recommendations
    print("\n" + "=" * 100)
    print("RECOMMENDATIONS")
    print("=" * 100)
    print("1. For maximum throughput: Use hash() method for single operations")
    print("2. For streaming: Use update() with 64KB-256KB chunks")
    print("3. SHA-256 is typically faster than SHA3-256")
    print("4. For small data (<1KB): initialization overhead is significant")
    print("5. For large files (>10MB): streaming with update() is most efficient")

    return {
        'throughput': throughput_results,
        'small_data': small_data_results,
        'streaming': streaming_results,
        'overhead': overhead_results
    }


if __name__ == "__main__":
    print("Starting hash function performance benchmark...")
    print("This will test SHA-256 and SHA3-256 with real throughput measurements.")
    print()

    try:
        report = generate_hash_performance_report()
        print("\n" + "=" * 100)
        print("BENCHMARK COMPLETE")
        print("=" * 100)

        # Save results to file
        import json
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        with open(f'hash_performance_{timestamp}.json', 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\nDetailed results saved to: hash_performance_{timestamp}.json")

    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
    except Exception as e:
        print(f"\nError during benchmark: {e}")
        import traceback
        traceback.print_exc()