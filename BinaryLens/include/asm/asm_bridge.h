#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// thin boundary around the hand-written asm helpers.
namespace bl::asmbridge
{
    enum StubFeatureFlags : std::uint32_t
    {
        stub_none = 0,
        stub_initial_jump = 1u << 0,
        stub_push_ret = 1u << 1,
        stub_call_pop = 1u << 2,
        stub_peb_access = 1u << 3,
        stub_syscall_sequence = 1u << 4,
        stub_decoder_loop = 1u << 5,
        stub_stack_pivot = 1u << 6,
        stub_sparse_padding = 1u << 7,
        stub_suspicious_branch_density = 1u << 8,
        stub_manual_mapping_hint = 1u << 9,
        stub_memory_walk_hint = 1u << 10
    };

    struct PatternScanResult
    {
        std::size_t firstMatchOffset = static_cast<std::size_t>(-1);
        std::size_t matchCount = 0;
        bool found = false;
    };

    struct EntrypointAsmProfile
    {
        std::uint32_t featureFlags = stub_none;
        std::uint32_t suspiciousOpcodeScore = 0;
        std::uint32_t branchOpcodeCount = 0;
        std::uint32_t memoryAccessPatternCount = 0;
    };

    bool IsAsmBackendAvailable();

    PatternScanResult FindPatternMasked(const std::uint8_t* buffer,
                                        std::size_t bufferSize,
                                        const std::uint8_t* pattern,
                                        const char* mask,
                                        std::size_t patternSize);

    EntrypointAsmProfile ProfileEntrypointStub(const std::uint8_t* code, std::size_t size);

    bool HasFeature(const EntrypointAsmProfile& profile, StubFeatureFlags flag);
    std::string DescribeEntrypointProfile(const EntrypointAsmProfile& profile);
}
