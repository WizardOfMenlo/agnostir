#include "merge_shuffle.h"

#include <algorithm>
#include <cstdint>

namespace {
void random_merge(
    std::vector<uint64_t>::iterator begin,
    std::vector<uint64_t>::iterator mid,
    std::vector<uint64_t>::iterator end,
    std::vector<uint64_t>::iterator buff_begin,
    BitStream& bits
) {
    auto left = begin;
    auto right = mid;
    auto out = buff_begin;

    size_t l_count = static_cast<size_t>(std::distance(left, mid));
    size_t r_count = static_cast<size_t>(std::distance(right, end));

    size_t l_left = l_count;
    size_t r_left = r_count;
    std::vector<uint8_t> choices;
    choices.reserve(l_count + r_count);

    while (l_left > 0 && r_left > 0) {
        const size_t total = l_left + r_left;
        const size_t mask = total - 1;
        const size_t pick = static_cast<size_t>(bits.next_u64()) & mask;

        if (pick < l_left) {
            choices.push_back(0);
            --l_left;
        } else {
            choices.push_back(1);
            --r_left;
        }
    }

    for (uint8_t choice : choices) {
        if (choice == 0) {
            *out++ = *left++;
        } else {
            *out++ = *right++;
        }
    }

    while (l_left > 0) { *out++ = *left++; --l_left; }
    while (r_left > 0) { *out++ = *right++; --r_left; }

    std::copy(buff_begin, out, begin);
}

void merge_shuffle_recursive(
    std::vector<uint64_t>::iterator begin,
    std::vector<uint64_t>::iterator end,
    std::vector<uint64_t>& aux,
    BitStream& bits
) {
    const size_t n = static_cast<size_t>(std::distance(begin, end));

    if (n <= g_fy_threshold) {
        fisher_yates_in_place(begin, end, bits);
        return;
    }

    auto mid = begin + static_cast<std::ptrdiff_t>(n / 2);

    merge_shuffle_recursive(begin, mid, aux, bits);
    merge_shuffle_recursive(mid, end, aux, bits);

    random_merge(begin, mid, end, aux.begin(), bits);
}
} // namespace

void merge_shuffle_driver(std::vector<uint64_t>& data, BitStream& bits) {
    std::vector<uint64_t> aux(data.size());
    merge_shuffle_recursive(data.begin(), data.end(), aux, bits);
}
