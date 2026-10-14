# k = 2^32 Detailed Results (After queried_elements multiplier change: 3 -> 2)

## Table 1: Top-Level Comparison

| Metric | BaseFold (Baseline) | Our IOPP (1 Codeswitch) |
|---|---:|---:|
| Total proof size (KB) | 9846.560 | 4008.864 |
| Total field elements | 82233.000 | 68366.000 |
| Total hashes | 225472.000 | 56911.000 |
| Total oracle length | 536854528 | 17179803648 |
| Improvement (KB) | - | 5837.696 |
| Improvement (%) | - | 59.29% |

## Table 2: Chosen Parameters

| Parameter | BaseFold (Baseline) | Our IOPP (1 Codeswitch) |
|---|---:|---:|
| eta | 32 | 64 |
| k0 exponent | 27 | 26 |
| k exponents chain | (27) | (26, 26) |
| k values chain | (134217728) | (67108864, 67108864) |
| eta * k0 | 4294967296 | 4294967296 |
| Basefold code (d,c,rate,delta,rounds) | (27,2,0.500000,0.152454,15) | (26,8,0.125000,0.739168,14) |
| ERA stage 0 (kexp,r,inv_rate,rate,delta,log_block_length) | N/A | (26,4,4.840000,0.206612,0.221817,28.275007) |

## Table 3: Component Contributions

| Component | BaseFold: field | BaseFold: hashes | BaseFold: oracle | Our IOPP: field | Our IOPP: hashes | Our IOPP: oracle |
|---|---:|---:|---:|---:|---:|---:|
| Starting IOR | 40352.000 | 23527 | 0 | 53216.000 | 16850 | 0 |
| Codeswitch #1 | 0 | 0 | 0 | 6672.000 | 7042 | 16106127360 |
| Basefold IOPP | 41881.000 | 201945 | 536854528 | 8478.000 | 33019 | 1073676288 |
| Starting IOR share of proof | 20.76% (2044.128 KB) | - | - | 55.93% (2242.112 KB) | - | - |
| Oracle split (codeswitch/basefold) | 0 / 536854528 | - | - | 16106127360 / 1073676288 | - | - |

## Table 4: Codeswitch Internal Breakdown (Our IOPP)

| Quantity | Value |
|---|---:|
| Indices queried (q) | 155 |
| b = inv_rate / r | 1.21 |
| ell_m = ceil(k / k') | 1 |
| ell_b = ceil(bk / k') | 2 |
| ell_g = ceil(sqrt(b)k / k') | 2 |
| ell_era = ceil(inv_rate*k / k') | 5 |
| Indexer oracles = ell_g + 3*ell_era | 17 |
| Online oracles = ell_m + ell_b + 2*ell_era | 13 |
| Total codeswitch oracles | 30 |
| Out block length (k' * c_out) | 536870912 |
| Oracle length = total_oracles * out_block_length | 16106127360 |
| Extra codeswitch field elements (term_1 + term_2_5 + term_6_8) | 2022 |
| Indexer queried field elements (indexer_oracles * q) | 2635 |
| Online queried field elements (online_oracles * q) | 2015 |
| Total codeswitch field elements | 6672 |
| Codeswitch hashes (top) | 153 |
| Codeswitch hashes (sibling) | 3368 |
| Total codeswitch hashes | 7042 |
