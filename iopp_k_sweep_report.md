# IOPP Sweep Results (Baseline vs 1 Codeswitch)

Runs: `k = eta*k0 = 2^24, 2^26, 2^28, 2^30, 2^32`; conjecture OFF; eta range `[2^4,2^14]`; baseline + 1 codeswitch only.

## Table 1: Best Proof Sizes Across k

| log2(k) | k | Baseline proof (KB) | 1-codeswitch proof (KB) | Improvement (KB) | Improvement (%) |
|---:|---:|---:|---:|---:|---:|
| 24 | 16777216 | 3588.640 | 2578.976 | 1009.664 | 28.14% |
| 26 | 67108864 | 4798.560 | 2951.008 | 1847.552 | 38.50% |
| 28 | 268435456 | 6298.720 | 3390.688 | 2908.032 | 46.17% |
| 30 | 1073741824 | 8151.968 | 3732.224 | 4419.744 | 54.22% |
| 32 | 4294967296 | 10450.400 | 4077.792 | 6372.608 | 60.98% |

## Table 2: Detailed Parameters and Totals for k = 2^30

| Metric | Baseline | 1 Codeswitch |
|---|---:|---:|
| eta | 32 | 64 |
| k0 exponent | 25 | 24 |
| k exponents chain | (25) | (24, 24) |
| k values chain | (33554432) | (16777216, 16777216) |
| eta * k0 | 1073741824 | 1073741824 |
| Total proof size (KB) | 8151.968 | 3732.224 |
| Total field elements | 86798.000 | 69156.000 |
| Total hashes | 167951.000 | 47476.000 |
| Total oracle length | 134201344 | 4294901760 |
| Basefold code (d,c,rate,delta,rounds) | (25,2,0.500000,0.163748,13) | (24,8,0.125000,0.745882,12) |
| ERA stage 0 (kexp,r,inv_rate,rate,delta,log_block_length) | N/A | (24,4,4.840000,0.206612,0.221692,26.275007) |

## Table 3: Detailed Component Contributions for k = 2^30

| Component | Baseline: field | Baseline: hashes | Baseline: oracle | 1 Codeswitch: field | 1 Codeswitch: hashes | 1 Codeswitch: oracle |
|---|---:|---:|---:|---:|---:|---:|
| Starting IOR | 37306.000 | 19556 | 0 | 53210.000 | 15190 | 0 |
| Codeswitch #1 | 0 | 0 | 0 | 6342.000 | 6306 | 4026531840 |
| Basefold IOPP | 49492.000 | 148395 | 134201344 | 9604.000 | 25980 | 268369920 |
| Starting IOR share of proof | 22.32% (1819.584 KB) | - | - | 58.65% (2188.800 KB) | - | - |
| Oracle split (codeswitch/basefold) | 0 / 134201344 | - | - | 4026531840 / 268369920 | - | - |