#include <algorithm>
#include <climits>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "baselines.h"
#include "merge_shuffle.h"
#include "radix_shuffle.h"
#include "utils.h"

int main(int argc, char** argv) {
    size_t vector_log2 = DEFAULT_VECTOR_LOG2;
    size_t fy_log2 = DEFAULT_FY_LOG2;

    if (argc > 3) {
        std::cerr << "Usage: " << argv[0] << " [vector_log2] [fy_threshold_log2]" << std::endl;
        return 1;
    }
    if (argc >= 2) {
        vector_log2 = static_cast<size_t>(std::strtoull(argv[1], nullptr, 10));
    }
    if (argc >= 3) {
        fy_log2 = static_cast<size_t>(std::strtoull(argv[2], nullptr, 10));
    }

    if (vector_log2 >= sizeof(size_t) * CHAR_BIT || fy_log2 >= sizeof(size_t) * CHAR_BIT) {
        std::cerr << "Error: log2 values must be less than " << (sizeof(size_t) * CHAR_BIT)
                  << std::endl;
        return 1;
    }

    const size_t vector_size = size_t(1) << vector_log2;
    g_fy_threshold = size_t(1) << fy_log2;

    std::cout << "Initializing vector with " << vector_size << " elements ("
              << (vector_size * sizeof(uint64_t)) / (1024 * 1024) << " MB)..." << std::endl;

    std::vector<uint64_t> data(vector_size);
    for (size_t i = 0; i < vector_size; ++i) data[i] = i;

    std::cout << "Initialization complete. Starting benchmark.\n" << std::endl;

    // --- Run Baseline ---
    {
        const size_t bit_count = std::max<size_t>(data.size(), 2);
        std::vector<uint64_t> bits = generate_random_bits(bit_count);
        BitStream bitstream(bits);
        std::cout << "Running Standard Fisher-Yates (std::shuffle)..." << std::flush;
        Timer t;
        baseline_shuffle(data, bitstream);
        double elapsed = t.elapsed();
        std::cout << " Done in " << elapsed << "s" << std::endl;
        std::cout << "  (Checksum: " << data[0] + data[vector_size/2] << ")" << std::endl;
    }

    // --- Run Baseline (Index Permutation + Gather) ---
    {
        const size_t bit_count = std::max<size_t>(data.size(), 2);
        std::vector<uint64_t> bits = generate_random_bits(bit_count);
        BitStream bitstream(bits);
        std::cout << "Running Index Permutation + Gather..." << std::flush;
        std::vector<uint64_t> gathered;
        Timer t;
        baseline_permute_indices(data, gathered, bitstream);
        double elapsed = t.elapsed();
        std::cout << " Done in " << elapsed << "s" << std::endl;
        std::cout << "  (Checksum: " << gathered[0] + gathered[vector_size/2] << ")" << std::endl;
    }

    // --- Run Optimized (Ping-Pong) ---
    {
        std::vector<uint64_t> data_copy_oop = data;
        const size_t levels = ceil_log2_size_t(data_copy_oop.size()) + 1;
        const size_t bit_count = std::max<size_t>(data_copy_oop.size() * levels / 32, 2);
        std::vector<uint64_t> bits = generate_random_bits(bit_count);
        BitStream bitstream(bits);
        std::cout << "Running Recursive Radix Shuffle (Ping-Pong)..." << std::flush;
        RadixStats stats;
        Timer t;
        optimized_shuffle_driver_oop(data_copy_oop, bitstream, stats);
        double elapsed = t.elapsed();
        std::cout << " Done in " << elapsed << "s" << std::endl;
        std::cout << "  Partition time: " << stats.partition_seconds << "s" << std::endl;
        std::cout << "  (Checksum: " << data_copy_oop[0] + data_copy_oop[vector_size/2] << ")" << std::endl;
    }

    // --- Run Merge Shuffle ---
    {
        std::vector<uint64_t> data_copy_merge = data;
        const size_t levels = ceil_log2_size_t(data_copy_merge.size()) + 1;
        const size_t bit_count = std::max<size_t>(data_copy_merge.size() * levels * 2, 2);
        std::vector<uint64_t> bits = generate_random_bits(bit_count);
        BitStream bitstream(bits);
        std::cout << "Running Merge Shuffle..." << std::flush;
        Timer t;
        merge_shuffle_driver(data_copy_merge, bitstream);
        double elapsed = t.elapsed();
        std::cout << " Done in " << elapsed << "s" << std::endl;
        std::cout << "  (Checksum: " << data_copy_merge[0] + data_copy_merge[vector_size/2] << ")" << std::endl;
    }

    return 0;
}
