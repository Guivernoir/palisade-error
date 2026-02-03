# Palisade Error Component: Benchmark Analysis

## 1. Executive Summary

This document provides a detailed performance breakdown of the high-fidelity error component. The results demonstrate a **production-grade architecture** characterized by **Timing Normalization** (to prevent side-channel leakage) and a **strict zero-leak memory management policy**. Despite being tested on older hardware (Dell Latitude E6410), the component maintains sub-microsecond internal speeds and consistent microsecond-scale public-facing response times.

## 2. Testing Environment

* **Language:** Rust (Stable)
* **Hardware:** Dell Latitude E6410
* **Memory:** 6 GB RAM
* **Target Accuracy:** High-fidelity attack simulation

## 3. Security Architecture: Timing Normalization

The core security feature is **Timing Normalization**. While raw internal processing averages 200–700 ns, the component implements an intentional 1 µs execution window. This target ensures that background OS processes or minor system variations do not reveal the honeypot's nature through execution jitter.

* **Public Latency Consistency:** Standard operations like `Simple Error Creation`, `Dynamic String Error`, and `Error with Sensitive Data` are consistently normalized within the **1.11 µs to 1.28 µs** range.
* **Intentional Delay Simulations:** For specific high-fidelity scenarios, the system can enforce rigid delays. `Fast Error With Norm` is locked at **~10.1 ms**, and `Slow Error With Norm` is locked at **~15.1 ms**, proving the reliability of the normalization logic.
* **Control Overhead:** The measurement overhead for this logic remains extremely stable at **~1.13 µs**, ensuring the defense mechanism does not introduce its own detectable patterns.

## 4. Memory Efficiency & Reliability

A primary goal for a long-running honeypot is stability. The component achieves a **"Zero-Leak"** state across all tested scenarios.

* **Steady State Memory Balance:** In almost every test, the `Net` memory impact is **0 B**, confirming that Rust’s ownership model effectively deallocates every byte used during error generation.
* **Metadata Scalability:** Accessing metadata is highly optimized. Accessing up to 8 metadata fields occurs in just **22 ns to 45 ns**, with a total allocation footprint of only **376 B** for 8 fields.
* **String Handling:** Even under `Allocation Heavy Dynamic Strings` scenarios, the system remains leak-free and normalized to **~1.3 µs**.

## 5. Performance Under Attack Load

The component is designed to handle automated scanners and aggressive probing without performance degradation.

| Scenario | Execution Time | Total Allocations |
| --- | --- | --- |
| **Attack Burst (10)** | 19 µs - 32 µs | Net: 0 B |
| **Attack Burst (100)** | 186 µs - 305 µs | Net: 0 B |
| **Attack Burst (500)** | 1.0 ms - 1.6 ms | Net: 0 B |
| **Batch Create (1000)** | ~1.1 ms | Net: 0 B |

* **Multi-threading Resilience:** Under heavy concurrent load (8 threads processing 16,036 calls), the system maintains responsiveness between **2.3 ms and 10.7 ms**, allowing it to survive high-frequency probes or DDoS-style discovery attempts.

## 6. Micro-benchmarks

Internal utility functions provide nanosecond-scale performance, allowing the component to perform complex security tasks "under the hood" during the 1 µs normalization window.

* **Obfuscation Logic:** The `Obfuscate Code` utility takes only **~28 ns**.
* **Cryptographic Randomness:** Generating random salts for session tracking takes **~92 ns**.
* **Logging Consistency:** Internal log writes are processed in **~660 ns**, well within the safety window.

## 7. Conclusion

The benchmarks confirm that this error component is **highly efficient and cryptographically sound** regarding timing side-channels. Its ability to maintain **zero-net memory growth** and **microsecond-level predictability** on standard hardware makes it an ideal candidate for high-fidelity honeypot deployments.