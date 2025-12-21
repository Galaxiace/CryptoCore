"""
Performance tests for AES encryption/decryption in various modes.
Shows real throughput numbers for different data sizes and modes.
"""

import time
import statistics
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import AES modules
from src.crypto.aes_ecb import AES_ECB_MODE
from src.crypto.modes.cbc import CBC_MODE
from src.crypto.modes.cfb import CFB_MODE
from src.crypto.modes.ofb import OFB_MODE
from src.crypto.modes.ctr import CTR_MODE
from src.crypto.modes.gcm import GCM_MODE
from src.utils.csprng import generate_random_bytes


def generate_test_data(size_bytes):
    """Generate test data of specified size"""
    return generate_random_bytes(size_bytes)


def benchmark_aes_mode(mode_class, key_size=16, data_size=1048576, iterations=5, warmup=3):
    """
    Benchmark single AES mode with detailed metrics

    Returns dictionary with performance metrics
    """
    # Generate test data
    key = generate_random_bytes(key_size)

    # Initialize mode
    if mode_class.__name__ == 'GCM_MODE':
        mode = GCM_MODE(key)
    elif mode_class.__name__ in ['CBC_MODE', 'CFB_MODE', 'OFB_MODE', 'CTR_MODE']:
        mode = mode_class(key)
    else:
        mode = AES_ECB_MODE(key)

    # Prepare data
    plaintext = generate_test_data(data_size)

    # Prepare IV
    iv = None
    if mode_class.__name__ in ['CBC_MODE', 'CFB_MODE', 'OFB_MODE', 'CTR_MODE']:
        iv = generate_random_bytes(16)
    elif mode_class.__name__ == 'GCM_MODE':
        iv = generate_random_bytes(12)
        aad = b"performance_test"

    # Warm-up
    for _ in range(warmup):
        if mode_class.__name__ == 'GCM_MODE':
            ciphertext = mode.encrypt(plaintext, iv=iv, aad=aad)
            _ = mode.decrypt(ciphertext, iv=iv, aad=aad)
        elif hasattr(mode, 'encrypt'):
            ciphertext = mode.encrypt(plaintext, iv=iv)
            _ = mode.decrypt(ciphertext, iv=iv)

    # Benchmark encryption
    enc_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        if mode_class.__name__ == 'GCM_MODE':
            ciphertext = mode.encrypt(plaintext, iv=iv, aad=aad)
        else:
            ciphertext = mode.encrypt(plaintext, iv=iv)
        enc_times.append(time.perf_counter() - start)

    # Benchmark decryption
    dec_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        if mode_class.__name__ == 'GCM_MODE':
            decrypted = mode.decrypt(ciphertext, iv=iv, aad=aad)
        else:
            decrypted = mode.decrypt(ciphertext, iv=iv)
        dec_times.append(time.perf_counter() - start)

    # Calculate metrics
    enc_mean = statistics.mean(enc_times)
    enc_std = statistics.stdev(enc_times) if len(enc_times) > 1 else 0
    dec_mean = statistics.mean(dec_times)
    dec_std = statistics.stdev(dec_times) if len(dec_times) > 1 else 0

    # Calculate throughput (MB/s)
    data_mb = data_size / (1024 * 1024)
    enc_throughput = data_mb / enc_mean if enc_mean > 0 else 0
    dec_throughput = data_mb / dec_mean if dec_mean > 0 else 0

    return {
        'mode': mode_class.__name__.replace('_MODE', ''),
        'key_size': key_size,
        'data_size_bytes': data_size,
        'data_size_mb': round(data_mb, 3),
        'iterations': iterations,

        # Encryption metrics
        'encryption_time_mean': round(enc_mean, 4),
        'encryption_time_std': round(enc_std, 4),
        'encryption_throughput': round(enc_throughput, 2),
        'encryption_speed': f"{enc_throughput:.2f} MB/s",

        # Decryption metrics
        'decryption_time_mean': round(dec_mean, 4),
        'decryption_time_std': round(dec_std, 4),
        'decryption_throughput': round(dec_throughput, 2),
        'decryption_speed': f"{dec_throughput:.2f} MB/s",

        # Overall
        'total_time': round(enc_mean + dec_mean, 4),
        'average_throughput': round((enc_throughput + dec_throughput) / 2, 2),
        'operations_per_second': round(1 / ((enc_mean + dec_mean) / 2), 1),
    }


def run_aes_throughput_comparison():
    """Compare throughput of all AES modes for different data sizes"""
    print("=" * 120)
    print("AES THROUGHPUT COMPARISON (Higher is Better)")
    print("=" * 120)

    modes = [
        (AES_ECB_MODE, "ECB"),
        (CBC_MODE, "CBC"),
        (CFB_MODE, "CFB"),
        (OFB_MODE, "OFB"),
        (CTR_MODE, "CTR"),
        (GCM_MODE, "GCM"),
    ]

    data_sizes = [
        16,  # 1 block
        1024,  # 1 KB
        16384,  # 16 KB
        65536,  # 64 KB
        262144,  # 256 KB
        1048576,  # 1 MB (как в требованиях)
    ]

    key_size = 16  # AES-128

    print(f"\n{'Mode':<6} {'Data Size':<12} {'Encryption (MB/s)':<18} {'Decryption (MB/s)':<18} {'Total Time (s)':<14}")
    print("-" * 120)

    results_by_mode = {}

    for mode_class, mode_name in modes:
        if mode_name == "GCM":
            print(f"{mode_name:<6} {'various':<12} {'See detailed test':<18} {'below':<18} {'':<14}")
            continue

        results_by_mode[mode_name] = []

        for data_size in data_sizes:
            try:
                result = benchmark_aes_mode(mode_class, key_size, data_size, iterations=3, warmup=2)
                results_by_mode[mode_name].append(result)

                # Format data size
                if data_size < 1024:
                    size_str = f"{data_size}B"
                elif data_size < 1024 * 1024:
                    size_str = f"{data_size // 1024}KB"
                else:
                    size_str = f"{data_size // (1024 * 1024)}MB"

                print(f"{mode_name:<6} {size_str:<12} {result['encryption_throughput']:>8.2f} MB/s     "
                      f"{result['decryption_throughput']:>8.2f} MB/s     "
                      f"{result['total_time']:>10.4f}")

            except Exception as e:
                print(f"{mode_name:<6} {size_str:<12} {'ERROR':<18} {str(e)[:30]:<18}")

    return results_by_mode


def benchmark_aes_key_sizes():
    """Benchmark AES with different key sizes"""
    print("\n" + "=" * 120)
    print("AES KEY SIZE PERFORMANCE COMPARISON (1MB Data)")
    print("=" * 120)

    modes = [
        (AES_ECB_MODE, "ECB"),
        (CBC_MODE, "CBC"),
        (CTR_MODE, "CTR"),
    ]

    key_sizes = [16, 24, 32]  # AES-128, AES-192, AES-256
    data_size = 1048576  # 1MB

    print(f"\n{'Mode':<6} {'Key Size':<10} {'Encryption (MB/s)':<18} {'Decryption (MB/s)':<18} {'Total Time (s)':<14}")
    print("-" * 120)

    results = {}

    for mode_class, mode_name in modes:
        results[mode_name] = {}

        for key_size in key_sizes:
            try:
                result = benchmark_aes_mode(mode_class, key_size, data_size, iterations=5, warmup=3)
                results[mode_name][key_size] = result

                key_str = f"AES-{key_size * 8}"
                print(f"{mode_name:<6} {key_str:<10} {result['encryption_throughput']:>8.2f} MB/s     "
                      f"{result['decryption_throughput']:>8.2f} MB/s     "
                      f"{result['total_time']:>10.4f}")

            except Exception as e:
                print(f"{mode_name:<6} AES-{key_size * 8:<10} {'ERROR':<18} {str(e)[:30]:<18}")

    return results


def run_gcm_performance_test():
    """Special performance test for GCM mode"""
    print("\n" + "=" * 120)
    print("GCM MODE PERFORMANCE TEST (Authentication + Encryption)")
    print("=" * 120)

    try:
        key = generate_random_bytes(16)
        gcm = GCM_MODE(key)

        data_sizes = [1024, 16384, 65536, 262144, 1048576]
        aad = b"authenticated_data"

        print(f"\n{'Data Size':<12} {'Encrypt+Auth (MB/s)':<20} {'Decrypt+Verify (MB/s)':<20} {'Total (MB/s)':<15}")
        print("-" * 120)

        results = []

        for data_size in data_sizes:
            plaintext = generate_test_data(data_size)

            # Benchmark
            enc_times = []
            dec_times = []

            for _ in range(5):
                # Encryption + Authentication
                start = time.perf_counter()
                iv = generate_random_bytes(12)
                ciphertext = gcm.encrypt(plaintext, iv=iv, aad=aad)
                enc_times.append(time.perf_counter() - start)

                # Decryption + Verification
                start = time.perf_counter()
                decrypted = gcm.decrypt(ciphertext, iv=iv, aad=aad)
                dec_times.append(time.perf_counter() - start)

            # Calculate throughput
            data_mb = data_size / (1024 * 1024)
            enc_throughput = data_mb / statistics.mean(enc_times) if enc_times else 0
            dec_throughput = data_mb / statistics.mean(dec_times) if dec_times else 0
            total_throughput = (enc_throughput + dec_throughput) / 2

            # Format data size
            if data_size < 1024:
                size_str = f"{data_size}B"
            elif data_size < 1024 * 1024:
                size_str = f"{data_size // 1024}KB"
            else:
                size_str = f"{data_size // (1024 * 1024)}MB"

            print(
                f"{size_str:<12} {enc_throughput:>10.2f} MB/s      {dec_throughput:>10.2f} MB/s      {total_throughput:>10.2f} MB/s")

            results.append({
                'data_size': data_size,
                'enc_throughput': enc_throughput,
                'dec_throughput': dec_throughput,
                'total_throughput': total_throughput
            })

        return results

    except Exception as e:
        print(f"GCM test failed: {e}")
        return None


def generate_performance_report():
    """Generate comprehensive performance report"""
    print("\n" + "=" * 120)
    print("CRYPTOCORE AES PERFORMANCE REPORT")
    print("=" * 120)
    print(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python: {sys.version}")
    print()

    # Run all benchmarks
    print("1. Throughput Comparison by Mode:")
    throughput_results = run_aes_throughput_comparison()

    print("\n2. Key Size Performance Impact:")
    key_size_results = benchmark_aes_key_sizes()

    print("\n3. GCM Mode Performance (Authenticated Encryption):")
    gcm_results = run_gcm_performance_test()

    # Summary
    print("\n" + "=" * 120)
    print("PERFORMANCE SUMMARY")
    print("=" * 120)

    # Calculate average performance
    all_throughputs = []
    for mode_results in throughput_results.values():
        for result in mode_results:
            all_throughputs.append(result['encryption_throughput'])
            all_throughputs.append(result['decryption_throughput'])

    if all_throughputs:
        avg_throughput = statistics.mean(all_throughputs)
        max_throughput = max(all_throughputs)
        min_throughput = min(all_throughputs)

        print(f"\nAverage throughput across all modes: {avg_throughput:.2f} MB/s")
        print(f"Maximum throughput: {max_throughput:.2f} MB/s")
        print(f"Minimum throughput: {min_throughput:.2f} MB/s")

    # Recommendations
    print("\n" + "=" * 120)
    print("RECOMMENDATIONS")
    print("=" * 120)
    print("1. For maximum speed: Use CTR or OFB mode")
    print("2. For authenticated encryption: Use GCM mode")
    print("3. For compatibility: Use CBC mode")
    print("4. For simple use cases: Use ECB mode (but avoid for sensitive data)")
    print("5. Key size impact: AES-128 provides best performance/safety balance")

    return {
        'throughput': throughput_results,
        'key_sizes': key_size_results,
        'gcm': gcm_results
    }


if __name__ == "__main__":
    print("Starting AES performance benchmark...")
    print("This will test all AES modes with real throughput measurements.")
    print()

    try:
        report = generate_performance_report()
        print("\n" + "=" * 120)
        print("BENCHMARK COMPLETE")
        print("=" * 120)

        # Save results to file
        import json

        timestamp = time.strftime('%Y%m%d_%H%M%S')
        with open(f'aes_performance_{timestamp}.json', 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\nDetailed results saved to: aes_performance_{timestamp}.json")

    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
    except Exception as e:
        print(f"\nError during benchmark: {e}")
        import traceback

        traceback.print_exc()