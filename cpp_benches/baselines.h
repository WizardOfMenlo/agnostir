#pragma once

#include <cstdint>
#include <vector>

#include "utils.h"

void baseline_shuffle(std::vector<uint64_t>& data, BitStream& bits);
void baseline_permute_indices(
    const std::vector<uint64_t>& input,
    std::vector<uint64_t>& output,
    BitStream& bits
);
