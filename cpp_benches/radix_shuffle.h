#pragma once

#include <cstdint>
#include <vector>

#include "utils.h"

struct RadixStats {
    double fisher_yates_seconds = 0.0;
    double partition_seconds = 0.0;
};

void optimized_shuffle_driver(std::vector<uint64_t>& data, BitStream& bits, RadixStats& stats);
void optimized_shuffle_driver_oop(
    std::vector<uint64_t>& data,
    BitStream& bits,
    RadixStats& stats
);
