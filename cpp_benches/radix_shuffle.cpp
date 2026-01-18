#include "radix_shuffle.h"

#include <algorithm>
#include <chrono>

namespace {
void radix_shuffle_recursive(
    std::vector<uint64_t>::iterator begin,
    std::vector<uint64_t>::iterator end,
    BitStream& bits,
    RadixStats& stats
) {
    const size_t count = static_cast<size_t>(std::distance(begin, end));

    if (count <= g_fy_threshold) {
        auto fy_start = std::chrono::high_resolution_clock::now();
        fisher_yates_in_place(begin, end, bits);
        auto fy_end = std::chrono::high_resolution_clock::now();
        stats.fisher_yates_seconds +=
            std::chrono::duration<double>(fy_end - fy_start).count();
        return;
    }

    auto left = begin;
    auto right = end - 1;

    uint64_t rand_bits = bits.next_u64();
    uint64_t bit_mask = 1;

    auto partition_start = std::chrono::high_resolution_clock::now();
    while (left <= right) {
        if (bit_mask == 0) {
            rand_bits = bits.next_u64();
            bit_mask = 1;
        }

        bool heads = (rand_bits & bit_mask);
        bit_mask <<= 1;

        if (heads) {
            ++left;
        } else {
            std::iter_swap(left, right);
            --right;
        }
    }
    auto partition_end = std::chrono::high_resolution_clock::now();
    stats.partition_seconds +=
        std::chrono::duration<double>(partition_end - partition_start).count();

    radix_shuffle_recursive(begin, left, bits, stats);
    radix_shuffle_recursive(left, end, bits, stats);
}

bool radix_ping_pong(
    std::vector<uint64_t>::iterator src_begin,
    std::vector<uint64_t>::iterator src_end,
    std::vector<uint64_t>::iterator dst_begin,
    BitStream& bits,
    RadixStats& stats
) {
    const size_t n = static_cast<size_t>(std::distance(src_begin, src_end));

    if (n <= g_fy_threshold) {
        fisher_yates_in_place(src_begin, src_end, bits);
        return false;
    }

    auto head = dst_begin;
    auto tail = dst_begin + n - 1;
    auto src_it = src_begin;

    uint64_t rand_bits = bits.next_u64();
    uint64_t bit_mask = 1;

    auto partition_start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < n; ++i) {
        if (bit_mask == 0) {
            rand_bits = bits.next_u64();
            bit_mask = 1;
        }

        if (rand_bits & bit_mask) {
            *head++ = *src_it++;
        } else {
            *tail-- = *src_it++;
        }
        bit_mask <<= 1;
    }
    auto partition_end = std::chrono::high_resolution_clock::now();
    stats.partition_seconds +=
        std::chrono::duration<double>(partition_end - partition_start).count();

    auto split_point = head;
    size_t left_count = static_cast<size_t>(std::distance(dst_begin, split_point));

    if (left_count == 0 || left_count == n) {
        fisher_yates_in_place(src_begin, src_end, bits);
        return false;
    }

    bool left_moved = radix_ping_pong(
        dst_begin,
        split_point,
        src_begin,
        bits,
        stats
    );

    bool right_moved = radix_ping_pong(
        split_point,
        dst_begin + n,
        src_begin + left_count,
        bits,
        stats
    );

    if (left_moved && right_moved) {
        return false;
    }

    if (!left_moved && !right_moved) {
        return true;
    }

    size_t right_count = n - left_count;

    if (left_moved) {
        if (left_count < right_count) {
            std::copy(src_begin, src_begin + left_count, dst_begin);
            return true;
        }

        std::copy(split_point, dst_begin + n, src_begin + left_count);
        return false;
    }

    if (left_count < right_count) {
        std::copy(dst_begin, split_point, src_begin);
        return false;
    }

    std::copy(src_begin + left_count, src_begin + n, split_point);
    return true;
}
} // namespace

void optimized_shuffle_driver(std::vector<uint64_t>& data, BitStream& bits, RadixStats& stats) {
    radix_shuffle_recursive(data.begin(), data.end(), bits, stats);
}

void optimized_shuffle_driver_oop(
    std::vector<uint64_t>& data,
    BitStream& bits,
    RadixStats& stats
) {
    std::vector<uint64_t> scratch(data.size());
    bool moved = radix_ping_pong(data.begin(), data.end(), scratch.begin(), bits, stats);
    if (moved) {
        std::copy(scratch.begin(), scratch.end(), data.begin());
    }
}
