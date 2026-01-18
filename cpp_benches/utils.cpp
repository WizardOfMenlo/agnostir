#include "utils.h"

size_t g_fy_threshold = size_t(1) << DEFAULT_FY_LOG2;

Timer::Timer() : start_time(Clock::now()) {}

double Timer::elapsed() {
    auto end_time = Clock::now();
    return std::chrono::duration<double>(end_time - start_time).count();
}

BitStream::BitStream(const std::vector<uint64_t>& data) : bits(&data) {}

uint64_t BitStream::next_u64() {
    if (bits->empty()) {
        return 0;
    }
    if (idx >= bits->size()) {
        idx = 0;
    }
    return (*bits)[idx++];
}

size_t uniform_u64(BitStream& bits, size_t bound) {
    const uint64_t x = bits.next_u64();
    return static_cast<size_t>((static_cast<unsigned __int128>(x) * bound) >> 64);
}

size_t ceil_log2_size_t(size_t n) {
    if (n <= 1) {
        return 0;
    }
    size_t p = 0;
    size_t v = n - 1;
    while (v > 0) {
        v >>= 1;
        ++p;
    }
    return p;
}

std::vector<uint64_t> generate_random_bits(size_t count) {
    std::random_device rd;
    std::mt19937_64 rng(rd());
    std::vector<uint64_t> bits(count);
    for (size_t i = 0; i < count; ++i) {
        bits[i] = rng();
    }
    return bits;
}
