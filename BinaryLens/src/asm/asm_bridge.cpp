#include "asm/asm_bridge.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

namespace
{
    using namespace bl::asmbridge;

    // keeps the masked scan path available when the native asm backend is not active.

    PatternScanResult FindPatternMaskedPortable(const std::uint8_t* buffer,
                                                std::size_t bufferSize,
                                                const std::uint8_t* pattern,
                                                const char* mask,
                                                std::size_t patternSize)
    {
        PatternScanResult result;
        if (!buffer || !pattern || !mask || patternSize == 0 || bufferSize < patternSize)
            return result;

        // keep the portable matcher simple so it mirrors the asm contract exactly.
        for (std::size_t i = 0; i + patternSize <= bufferSize; ++i)
        {
            bool match = true;
            for (std::size_t j = 0; j < patternSize; ++j)
            {
                const char rule = mask[j];
                if (rule != '?' && buffer[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }

            if (!match)
                continue;

            if (!result.found)
            {
                result.firstMatchOffset = i;
                result.found = true;
            }
            ++result.matchCount;
        }

        return result;
    }

    // counts nop, zero, and breakpoint padding density inside the profiled entrypoint window.
    std::uint32_t CountSparsePadding(const std::uint8_t* code, std::size_t size)
    {
        std::uint32_t count = 0;
        for (std::size_t i = 0; i < size; ++i)
        {
            if (code[i] == 0x00 || code[i] == 0x90 || code[i] == 0xCC)
                ++count;
        }
        return count;
    }

    // mirrors the asm profiler so low-level entrypoint heuristics stay available across non-msvc builds.
    EntrypointAsmProfile ProfileEntrypointStubPortable(const std::uint8_t* code, std::size_t size)
    {
        EntrypointAsmProfile profile;
        if (!code || size == 0)
            return profile;

        // only the opening window is profiled because loader stubs usually reveal themselves there.
        const std::size_t boundedSize = (std::min)(size, static_cast<std::size_t>(64));

        // redirection opcodes at byte zero are a strong early stub hint.
        if (boundedSize >= 1 && (code[0] == 0xE9 || code[0] == 0xEB || code[0] == 0xFF))
        {
            profile.featureFlags |= stub_initial_jump;
            profile.suspiciousOpcodeScore += 4;
            ++profile.branchOpcodeCount;
        }

        if (boundedSize >= 6 && code[0] == 0x68 && code[5] == 0xC3)
        {
            profile.featureFlags |= stub_push_ret;
            profile.suspiciousOpcodeScore += 5;
        }

        // pair-based checks catch small resolver patterns without full disassembly.
        for (std::size_t i = 0; i + 1 < boundedSize; ++i)
        {
            const std::uint8_t a = code[i];
            const std::uint8_t b = code[i + 1];

            if (a == 0xE8)
            {
                ++profile.branchOpcodeCount;
                if (i + 5 < boundedSize && code[i + 5] == 0x58)
                {
                    profile.featureFlags |= stub_call_pop;
                    profile.suspiciousOpcodeScore += 4;
                }
            }

            if (a == 0x0F && (b == 0x05 || b == 0x34))
            {
                profile.featureFlags |= stub_syscall_sequence;
                profile.suspiciousOpcodeScore += 5;
            }

            if (a == 0x64 && b == 0xA1)
            {
                profile.featureFlags |= stub_peb_access;
                profile.suspiciousOpcodeScore += 4;
                ++profile.memoryAccessPatternCount;
            }

            if (a == 0x65 && i + 3 < boundedSize)
            {
                if ((b == 0x48 || b == 0x4C) && code[i + 2] == 0x8B)
                {
                    profile.featureFlags |= stub_peb_access;
                    profile.suspiciousOpcodeScore += 4;
                    ++profile.memoryAccessPatternCount;
                }
            }

            if ((a == 0x8B || a == 0x48 || a == 0x4C || a == 0x89 || a == 0x8D) && b == 0x04)
            {
                profile.featureFlags |= stub_memory_walk_hint;
                ++profile.memoryAccessPatternCount;
            }
        }

        // very small xor-write loops can suggest decoder-style entry stubs.
        for (std::size_t i = 0; i + 4 < boundedSize; ++i)
        {
            if ((code[i] == 0x31 || code[i] == 0x33) && (code[i + 2] == 0x88 || code[i + 2] == 0x30 || code[i + 2] == 0x32))
            {
                profile.featureFlags |= stub_decoder_loop;
                profile.suspiciousOpcodeScore += 3;
                break;
            }
        }

        for (std::size_t i = 0; i + 2 < boundedSize; ++i)
        {
            if (code[i] == 0x94 || (code[i] == 0x87 && code[i + 1] == 0x24))
            {
                profile.featureFlags |= stub_stack_pivot;
                profile.suspiciousOpcodeScore += 4;
                break;
            }
        }

        // manual-mapping hints are weaker, so they add only a small score bump.
        for (std::size_t i = 0; i + 3 < boundedSize; ++i)
        {
            if ((code[i] == 0x48 || code[i] == 0x4C) && code[i + 1] == 0x8B && code[i + 2] == 0x54)
            {
                profile.featureFlags |= stub_manual_mapping_hint;
                profile.suspiciousOpcodeScore += 2;
                ++profile.memoryAccessPatternCount;
            }
        }

        for (std::size_t i = 0; i < boundedSize; ++i)
        {
            if (code[i] == 0xE8 || code[i] == 0xE9 || code[i] == 0xEB || code[i] == 0x70 || code[i] == 0x71 || code[i] == 0x72 || code[i] == 0x73 || code[i] == 0x74 || code[i] == 0x75)
                ++profile.branchOpcodeCount;
        }

        if (profile.branchOpcodeCount >= 4)
        {
            profile.featureFlags |= stub_suspicious_branch_density;
            profile.suspiciousOpcodeScore += 2;
        }

        if (CountSparsePadding(code, boundedSize) >= 10)
        {
            profile.featureFlags |= stub_sparse_padding;
            profile.suspiciousOpcodeScore += 2;
        }

        return profile;
    }

#if defined(_MSC_VER) && defined(_M_X64)
extern "C" void BL_FindPatternMasked_Asm(const std::uint8_t* buffer,
                                         std::size_t bufferSize,
                                         const std::uint8_t* pattern,
                                         const char* mask,
                                         std::size_t patternSize,
                                         PatternScanResult* outResult);

extern "C" void BL_ProfileEntrypointStub_Asm(const std::uint8_t* code,
                                              std::size_t size,
                                              EntrypointAsmProfile* outProfile);
#endif
}

namespace bl::asmbridge
{
    bool IsAsmBackendAvailable()
    {
#if defined(_MSC_VER) && defined(_M_X64)
        return true;
#else
        return false;
#endif
    }

    PatternScanResult FindPatternMasked(const std::uint8_t* buffer,
                                        std::size_t bufferSize,
                                        const std::uint8_t* pattern,
                                        const char* mask,
                                        std::size_t patternSize)
    {
#if defined(_MSC_VER) && defined(_M_X64)
        PatternScanResult result;
        BL_FindPatternMasked_Asm(buffer, bufferSize, pattern, mask, patternSize, &result);
        return result;
#else
        return FindPatternMaskedPortable(buffer, bufferSize, pattern, mask, patternSize);
#endif
    }

    EntrypointAsmProfile ProfileEntrypointStub(const std::uint8_t* code, std::size_t size)
    {
#if defined(_MSC_VER) && defined(_M_X64)
        EntrypointAsmProfile profile;
        BL_ProfileEntrypointStub_Asm(code, size, &profile);
        return profile;
#else
        return ProfileEntrypointStubPortable(code, size);
#endif
    }

    bool HasFeature(const EntrypointAsmProfile& profile, StubFeatureFlags flag)
    {
        return (profile.featureFlags & static_cast<std::uint32_t>(flag)) != 0;
    }

    std::string DescribeEntrypointProfile(const EntrypointAsmProfile& profile)
    {
        std::vector<std::string> labels;

        if (HasFeature(profile, stub_initial_jump))
            labels.emplace_back("initial jump redirection");
        if (HasFeature(profile, stub_push_ret))
            labels.emplace_back("push-ret transfer");
        if (HasFeature(profile, stub_call_pop))
            labels.emplace_back("call-pop resolver");
        if (HasFeature(profile, stub_peb_access))
            labels.emplace_back("peb access pattern");
        if (HasFeature(profile, stub_syscall_sequence))
            labels.emplace_back("syscall sequence");
        if (HasFeature(profile, stub_decoder_loop))
            labels.emplace_back("decoder-like loop");
        if (HasFeature(profile, stub_stack_pivot))
            labels.emplace_back("stack pivot behavior");
        if (HasFeature(profile, stub_sparse_padding))
            labels.emplace_back("sparse padded stub");
        if (HasFeature(profile, stub_suspicious_branch_density))
            labels.emplace_back("dense branch layout");
        if (HasFeature(profile, stub_manual_mapping_hint))
            labels.emplace_back("manual mapping hint");
        if (HasFeature(profile, stub_memory_walk_hint))
            labels.emplace_back("memory walk hint");

        // the description is only meant for reports, so keep it flat and compact.
        if (labels.empty())
            return {};

        std::ostringstream oss;
        for (std::size_t i = 0; i < labels.size(); ++i)
        {
            if (i > 0)
                oss << ", ";
            oss << labels[i];
        }
        return oss.str();
    }
}
