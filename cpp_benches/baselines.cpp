#include "baselines.h"

#include <algorithm>

void baseline_shuffle(std::vector<uint64_t>& data, BitStream& bits) {
    fisher_yates_in_place(data.begin(), data.end(), bits);
}

void baseline_permute_indices(
    const std::vector<uint64_t>& input,
    std::vector<uint64_t>& output,
    BitStream& bits
) {
    const size_t n = input.size();
    output.resize(n);

    std::vector<size_t> indices(n);
    for (size_t i = 0; i < n; ++i) {
        indices[i] = i;
    }

    for (size_t i = n; i > 1; --i) {
        const size_t j = uniform_u64(bits, i);
        std::swap(indices[i - 1], indices[j]);
    }

    for (size_t i = 0; i < n; ++i) {
        output[i] = input[indices[i]];
    }
}
