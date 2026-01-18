#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <random>
#include <vector>

// --- Configuration (defaults are log2 values) ---
constexpr size_t DEFAULT_VECTOR_LOG2 = 28;
constexpr size_t DEFAULT_FY_LOG2 = 20;

// Cache Threshold: Switch to Fisher-Yates when data fits in L2 Cache
extern size_t g_fy_threshold;

// --- Timer Helper ---
class Timer {
    using Clock = std::chrono::high_resolution_clock;
    Clock::time_point start_time;

public:
    Timer();
    double elapsed();
};

struct BitStream {
    const std::vector<uint64_t>* bits = nullptr;
    size_t idx = 0;

    explicit BitStream(const std::vector<uint64_t>& data);
    uint64_t next_u64();
};

// Fisher-Yates shuffle using a pre-generated bitstream.
size_t uniform_u64(BitStream& bits, size_t bound);

template <typename It>
void fisher_yates_in_place(It begin, It end, BitStream& bits) {
    const size_t n = static_cast<size_t>(std::distance(begin, end));
    for (size_t i = n; i > 1; --i) {
        const size_t j = uniform_u64(bits, i);
        std::iter_swap(begin + static_cast<std::ptrdiff_t>(i - 1),
                       begin + static_cast<std::ptrdiff_t>(j));
    }
}

size_t ceil_log2_size_t(size_t n);
std::vector<uint64_t> generate_random_bits(size_t count);
