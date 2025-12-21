#!/usr/bin/env python3
"""
Расширенный тест производительности PBKDF2
"""

import time
import statistics
import hashlib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.kdf.pbkdf2 import pbkdf2_hmac_sha256


def measure_performance(func, *args, warmup_runs=3, test_runs=5):
    """Точное измерение производительности"""
    # Прогрев
    for _ in range(warmup_runs):
        func(*args)

    # Измерение
    times = []
    for _ in range(test_runs):
        start = time.perf_counter()
        result = func(*args)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    return {
        'min': min(times),
        'max': max(times),
        'mean': statistics.mean(times),
        'median': statistics.median(times),
        'stdev': statistics.stdev(times) if len(times) > 1 else 0,
        'result': result
    }


def benchmark_comprehensive():
    """Комплексный бенчмарк"""
    print("=" * 70)
    print("КОМПЛЕКСНЫЙ ТЕСТ ПРОИЗВОДИТЕЛЬНОСТИ PBKDF2")
    print("=" * 70)

    test_configs = [
        ("Small (1K)", "test", "salt", 1000, 32),
        ("Medium (10K)", "password123", "saltSALT", 10000, 32),
        ("Large (100K)", "VeryLongPasswordForTesting", "ComplexSalt123", 100000, 32),
    ]

    for name, pwd, salt, iters, dklen in test_configs:
        print(f"\n {name} - {iters:,} iterations")
        print("-" * 50)

        # Наша реализация
        print("Our implementation:")
        our_stats = measure_performance(
            pbkdf2_hmac_sha256, pwd, salt, iters, dklen
        )
        print(f"  Time: {our_stats['mean']:.3f}s "
              f"(min: {our_stats['min']:.3f}s, max: {our_stats['max']:.3f}s)")
        print(f"  Per iteration: {our_stats['mean'] / iters * 1000:.3f}ms")

        # Python hashlib
        print("\nPython hashlib (reference):")

        def hash_func():
            return hashlib.pbkdf2_hmac(
                'sha256',
                pwd.encode('utf-8'),
                salt.encode('utf-8'),
                iters,
                dklen
            )

        ref_stats = measure_performance(hash_func)
        print(f"  Time: {ref_stats['mean']:.3f}s "
              f"(min: {ref_stats['min']:.3f}s, max: {ref_stats['max']:.3f}s)")
        print(f"  Per iteration: {ref_stats['mean'] / iters * 1000:.3f}ms")

        # Сравнение
        if ref_stats['mean'] > 0:
            ratio = our_stats['mean'] / ref_stats['mean']
            print(f"\n  Performance ratio: {ratio:.2f}x "
                  f"({'slower' if ratio > 1 else 'faster'})")

            if our_stats['result'] == ref_stats['result']:
                print("   Results match")
            else:
                print("   Results DO NOT match!")

        print(f"  First 8 bytes: {our_stats['result'][:8].hex()}...")


def benchmark_iteration_scaling():
    """Тест масштабирования по итерациям"""
    print("\n\n МАСШТАБИРУЕМОСТЬ ПО КОЛИЧЕСТВУ ИТЕРАЦИЙ")
    print("=" * 50)

    password = "benchmark_password"
    salt = "0011223344556677"
    dklen = 32

    iteration_counts = [100, 500, 1000, 5000, 10000, 50000]

    print(f"{'Iterations':>12} | {'Our Time (s)':>12} | {'Hashlib (s)':>12} | {'Ratio':>8}")
    print("-" * 60)

    for iters in iteration_counts:
        # Наша реализация
        start = time.perf_counter()
        our_result = pbkdf2_hmac_sha256(password, salt, iters, dklen)
        our_time = time.perf_counter() - start

        # Hashlib
        start = time.perf_counter()
        ref_result = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            bytes.fromhex(salt),
            iters,
            dklen
        )
        ref_time = time.perf_counter() - start

        ratio = our_time / ref_time if ref_time > 0 else 0

        print(f"{iters:>12,} | {our_time:>12.3f} | {ref_time:>12.3f} | {ratio:>8.2f}x")

        # Проверка корректности
        if our_result != ref_result:
            print(f"  ⚠️  Warning: Results differ for {iters} iterations!")


def verify_million_iterations():
    """Проверка требования KDF-1 (1,000,000 итераций)"""
    print("\n\n ПРОВЕРКА ТРЕБОВАНИЯ KDF-1 (1,000,000 итераций)")
    print("=" * 50)

    password = "test"
    salt = "73616c74"  # "salt" in hex
    dklen = 32

    try:
        print("Running 1,000,000 iterations... (this may take a while)")
        start = time.perf_counter()
        result = pbkdf2_hmac_sha256(password, salt, 1000000, dklen)
        elapsed = time.perf_counter() - start

        print(f" Successfully completed 1,000,000 iterations")
        print(f"   Time: {elapsed:.2f} seconds")
        print(f"   Per iteration: {elapsed / 1000000 * 1000:.3f} ms")
        print(f"   Result (first 8 bytes): {result[:8].hex()}...")

        # Проверка длины
        assert len(result) == dklen, f"Wrong length: {len(result)} != {dklen}"

        return True

    except Exception as e:
        print(f" Failed to run 1,000,000 iterations: {e}")
        return False


if __name__ == '__main__':
    print("Расширенный тест производительности PBKDF2")
    print("Это может занять несколько минут...\n")

    start_total = time.perf_counter()

    try:
        benchmark_comprehensive()
        benchmark_iteration_scaling()

        if verify_million_iterations():
            print("\n ТРЕБОВАНИЕ KDF-1 ВЫПОЛНЕНО: Поддерживает 1,000,000 итераций")

        total_time = time.perf_counter() - start_total
        print(f"\n  Общее время тестирования: {total_time:.2f} секунд")
        print("\n" + "=" * 70)
        print(" ВСЕ ТЕСТЫ ПРОИЗВОДИТЕЛЬНОСТИ ЗАВЕРШЕНЫ")
        print("=" * 70)

    except KeyboardInterrupt:
        print("\n\nТест прерван")
    except Exception as e:
        print(f"\n\nОшибка: {e}")
        import traceback

        traceback.print_exc()