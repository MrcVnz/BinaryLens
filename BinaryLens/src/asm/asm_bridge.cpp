#include "asm/asm_bridge.h"

#include "common/string_utils.h"
#include "core/low_level_semantics.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace
{
    using namespace bl::asmbridge;

    std::uint8_t FoldAscii(std::uint8_t value)
    {
        if (value >= 'A' && value <= 'Z')
            return static_cast<std::uint8_t>(value | 0x20u);
        return value;
    }

    double SafeRatio(std::uint64_t value, std::uint64_t total)
    {
        if (total == 0)
            return 0.0;
        return static_cast<double>(value) / static_cast<double>(total);
    }

    std::string TrimAsciiCopy(const char* value)
    {
        if (!value)
            return {};

        std::string textValue(value);
        const auto first = textValue.find_first_not_of(' ');
        if (first == std::string::npos)
            return {};
        const auto last = textValue.find_last_not_of(' ');
        return textValue.substr(first, last - first + 1);
    }


    std::string JoinLabels(const std::vector<std::string>& labels)
    {
        std::ostringstream oss;
        for (std::size_t i = 0; i < labels.size(); ++i)
        {
            if (i > 0)
                oss << ", ";
            oss << labels[i];
        }
        return oss.str();
    }

    // keep key insertion centralized so the schema stays deduplicated even when multiple heuristics agree.
    void AddSignalKey(std::vector<std::string>& items, const std::string& value)
    {
        bl::common::AddUnique(items, value, 48);
    }

    void AddReason(std::vector<std::string>& items, const std::string& value)
    {
        bl::common::AddUnique(items, value, 24);
    }

    void AppendFeatureReason(const EntrypointAsmProfile& profile,
                             StubFeatureFlags flag,
                             const char* key,
                             const char* reason,
                             AsmEntrypointProfile& report)
    {
        if (!HasFeature(profile, flag))
            return;

        AddSignalKey(report.signals, key);
        AddReason(report.notes, reason);
    }

    bool MatchTokenIgnoreCase(const std::uint8_t* buffer, std::size_t size, const char* token)
    {
        if (!buffer || !token)
            return false;

        const std::size_t tokenSize = std::strlen(token);
        if (tokenSize == 0 || size < tokenSize)
            return false;

        for (std::size_t i = 0; i < tokenSize; ++i)
        {
            if (FoldAscii(buffer[i]) != static_cast<std::uint8_t>(token[i]))
                return false;
        }
        return true;
    }

    bool LooksLikeIpv4Portable(const std::uint8_t* buffer, std::size_t size)
    {
        if (!buffer || size < 7)
            return false;

        const std::size_t bounded = (std::min)(size, static_cast<std::size_t>(15));
        std::size_t consumed = 0;
        std::size_t dots = 0;
        std::size_t digits = 0;

        while (consumed < bounded)
        {
            const std::uint8_t c = buffer[consumed];
            if (c >= '0' && c <= '9')
            {
                ++digits;
            }
            else if (c == '.')
            {
                ++dots;
            }
            else
            {
                break;
            }
            ++consumed;
        }

        return consumed >= 7 && dots == 3 && digits >= 4;
    }

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
            }
        }

        for (std::size_t i = 0; i + 1 < boundedSize; ++i)
        {
            if (code[i] == 0x94)
            {
                profile.featureFlags |= stub_stack_pivot;
                profile.suspiciousOpcodeScore += 4;
            }

            if (code[i] == 0x87 && code[i + 1] == 0x24)
            {
                profile.featureFlags |= stub_stack_pivot;
                profile.suspiciousOpcodeScore += 4;
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

    CpuRuntimeInfo QueryCpuRuntimePortable()
    {
        CpuRuntimeInfo info = {};
        constexpr char vendorLabel[] = "portable";
        constexpr char brandLabel[] = "portable fallback";
        std::memcpy(info.vendor, vendorLabel, sizeof(vendorLabel));
        std::memcpy(info.brand, brandLabel, sizeof(brandLabel));
        return info;
    }

    LowLevelBufferProfile ProfileBufferLowLevelPortable(const std::uint8_t* buffer, std::size_t size)
    {
        LowLevelBufferProfile profile;
        if (!buffer || size == 0)
            return profile;

        profile.sampleBytes = static_cast<std::uint64_t>(size);

        std::uint8_t previous = 0;
        std::uint64_t repeatedRunLength = 0;
        std::uint64_t zeroRunLength = 0;
        std::uint64_t printableRunLength = 0;

        for (std::size_t i = 0; i < size; ++i)
        {
            const std::uint8_t value = buffer[i];

            if (value == 0x00)
                ++profile.zeroByteCount;
            if (value == 0xFF)
                ++profile.ffByteCount;
            if (value >= 32 && value <= 126)
                ++profile.printableAsciiCount;
            else if (value < 32 || value == 127)
                ++profile.controlByteCount;
            else
                ++profile.highByteCount;

            if (i == 0)
            {
                repeatedRunLength = 1;
            }
            else if (value == previous)
            {
                ++repeatedRunLength;
            }
            else
            {
                ++profile.transitionCount;
                if (repeatedRunLength >= 4)
                    ++profile.repeatedByteRunCount;
                repeatedRunLength = 1;
            }

            if (value == 0x00)
            {
                ++zeroRunLength;
                profile.longestZeroRun = (std::max)(profile.longestZeroRun, zeroRunLength);
            }
            else
            {
                zeroRunLength = 0;
            }

            if (value >= 32 && value <= 126)
            {
                ++printableRunLength;
                profile.longestPrintableRun = (std::max)(profile.longestPrintableRun, printableRunLength);
            }
            else
            {
                printableRunLength = 0;
            }

            previous = value;
        }

        if (repeatedRunLength >= 4)
            ++profile.repeatedByteRunCount;

        return profile;
    }

    AsciiTokenProfile ScanAsciiTokensPortable(const std::uint8_t* buffer, std::size_t size)
    {
        AsciiTokenProfile profile;
        if (!buffer || size == 0)
            return profile;

        for (std::size_t i = 0; i < size; ++i)
        {
            const std::size_t remaining = size - i;
            const std::uint8_t current = FoldAscii(buffer[i]);

            if (buffer[i] == '@')
                ++profile.emailMarkerHits;

            if (current == 'h')
            {
                if (MatchTokenIgnoreCase(buffer + i, remaining, "https"))
                {
                    ++profile.httpsHits;
                    ++profile.urlLikeHits;
                }
                else if (MatchTokenIgnoreCase(buffer + i, remaining, "http"))
                {
                    ++profile.httpHits;
                    ++profile.urlLikeHits;
                }

                if (MatchTokenIgnoreCase(buffer + i, remaining, "hklm\\") ||
                    MatchTokenIgnoreCase(buffer + i, remaining, "hkcu\\"))
                {
                    ++profile.registryHits;
                }
            }
            else if (current == 'w')
            {
                if (MatchTokenIgnoreCase(buffer + i, remaining, "www."))
                {
                    ++profile.wwwHits;
                    ++profile.urlLikeHits;
                }
            }
            else if (current == 'p')
            {
                if (MatchTokenIgnoreCase(buffer + i, remaining, "powershell"))
                    ++profile.powershellHits;
            }
            else if (current == 'c')
            {
                if (MatchTokenIgnoreCase(buffer + i, remaining, "cmd.exe"))
                {
                    ++profile.cmdExeHits;
                    ++profile.executableHits;
                }
            }
            else if (current == '.')
            {
                if (MatchTokenIgnoreCase(buffer + i, remaining, ".exe"))
                    ++profile.executableHits;
                else if (MatchTokenIgnoreCase(buffer + i, remaining, ".dll"))
                    ++profile.dynamicLibraryHits;
                else if (MatchTokenIgnoreCase(buffer + i, remaining, ".ps1") ||
                         MatchTokenIgnoreCase(buffer + i, remaining, ".bat") ||
                         MatchTokenIgnoreCase(buffer + i, remaining, ".vbs"))
                    ++profile.scriptExtensionHits;
            }

            if (buffer[i] >= '0' && buffer[i] <= '9' && LooksLikeIpv4Portable(buffer + i, remaining))
                ++profile.ipv4LikeHits;
        }

        return profile;
    }

    CodeSurfaceProfile ProfileCodeSurfacePortable(const std::uint8_t* code, std::size_t size)
    {
        CodeSurfaceProfile profile;
        if (!code || size == 0)
            return profile;

        for (std::size_t i = 0; i < size; ++i)
        {
            const std::uint8_t value = code[i];
            if (value == 0xE8 || value == 0xE9 || value == 0xEB || (value >= 0x70 && value <= 0x7F))
                ++profile.branchOpcodeCount;
            else if (value == 0x0F && i + 1 < size && code[i + 1] >= 0x80 && code[i + 1] <= 0x8F)
                ++profile.branchOpcodeCount;

            if (value == 0xC2 || value == 0xC3)
                ++profile.retOpcodeCount;
            if (value == 0x90)
                ++profile.nopOpcodeCount;
            if (value == 0xCC)
                ++profile.int3OpcodeCount;

            if (i + 2 < size && value == 0x55 && code[i + 1] == 0x48 && (code[i + 2] == 0x89 || code[i + 2] == 0x8B))
                ++profile.stackFrameHintCount;
            if (i + 2 < size && value == 0x48 && (code[i + 1] == 0x8D || code[i + 1] == 0x8B) && code[i + 2] == 0x05)
                ++profile.ripRelativeHintCount;
        }

        return profile;
    }

    OpcodeFamilyProfile ProfileOpcodeFamiliesPortable(const std::uint8_t* code, std::size_t size)
    {
        OpcodeFamilyProfile profile;
        if (!code || size == 0)
            return profile;

        for (std::size_t i = 0; i < size; ++i)
        {
            const std::uint8_t value = code[i];

            if (value == 0xE8 || value == 0xE9 || value == 0xEB || (value >= 0x70 && value <= 0x7F) ||
                value == 0xC2 || value == 0xC3 || value == 0xCC || value == 0xCD ||
                value == 0xE0 || value == 0xE1 || value == 0xE2 || value == 0xE3)
            {
                ++profile.controlTransferCount;
            }
            else if (value == 0x0F && i + 1 < size && code[i + 1] >= 0x80 && code[i + 1] <= 0x8F)
            {
                ++profile.controlTransferCount;
            }
            else if (value == 0xFF)
            {
                ++profile.controlTransferCount;
            }

            if ((value >= 0x50 && value <= 0x5F) || value == 0x68 || value == 0x6A || value == 0x9C || value == 0x9D || value == 0xC8 || value == 0xC9)
                ++profile.stackOperationCount;

            if (value == 0x8A || value == 0x8B || value == 0x88 || value == 0x89 || value == 0x8D || value == 0xA0 || value == 0xA1 ||
                value == 0xA2 || value == 0xA3 || value == 0xA4 || value == 0xA5 || value == 0xC6 || value == 0xC7)
                ++profile.memoryTouchCount;

            if ((value >= 0x00 && value <= 0x05) || (value >= 0x08 && value <= 0x0D) ||
                (value >= 0x20 && value <= 0x25) || (value >= 0x28 && value <= 0x2D) ||
                (value >= 0x30 && value <= 0x35) || value == 0x80 || value == 0x81 || value == 0x83 ||
                (value >= 0x40 && value <= 0x4F) || value == 0xD0 || value == 0xD1 || value == 0xD2 || value == 0xD3)
                ++profile.arithmeticLogicCount;

            if ((value >= 0x38 && value <= 0x3D) || value == 0x84 || value == 0x85 || value == 0xA8 || value == 0xA9)
                ++profile.compareTestCount;

            if (value == 0xE0 || value == 0xE1 || value == 0xE2 || value == 0xE3)
                ++profile.loopLikeCount;
            else if ((value >= 0x70 && value <= 0x7F) || (value == 0x0F && i + 1 < size && code[i + 1] >= 0x80 && code[i + 1] <= 0x8F))
                ++profile.loopLikeCount;

            if ((value == 0x0F && i + 1 < size && (code[i + 1] == 0x05 || code[i + 1] == 0x34)) || value == 0xCC || value == 0xCD || value == 0xCE)
                ++profile.syscallInterruptCount;

            if (value == 0xA4 || value == 0xA5 || value == 0xA6 || value == 0xA7 || value == 0xAA || value == 0xAB || value == 0xAC || value == 0xAD || value == 0xAE || value == 0xAF)
                ++profile.stringInstructionCount;
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

extern "C" void BL_QueryCpuRuntime_Asm(CpuRuntimeInfo* outInfo);

extern "C" void BL_ProfileBufferLowLevel_Asm(const std::uint8_t* buffer,
                                             std::size_t size,
                                             LowLevelBufferProfile* outProfile);

extern "C" void BL_ScanAsciiTokens_Asm(const std::uint8_t* buffer,
                                       std::size_t size,
                                       AsciiTokenProfile* outProfile);

extern "C" void BL_ProfileCodeSurface_Asm(const std::uint8_t* code,
                                          std::size_t size,
                                          CodeSurfaceProfile* outProfile);

extern "C" void BL_ProfileOpcodeFamilies_Asm(const std::uint8_t* code,
                                              std::size_t size,
                                              OpcodeFamilyProfile* outProfile);
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

    CpuRuntimeInfo QueryCpuRuntimeInfo()
    {
#if defined(_MSC_VER) && defined(_M_X64)
        static const CpuRuntimeInfo cached = []()
        {
            CpuRuntimeInfo info = {};
            BL_QueryCpuRuntime_Asm(&info);
            if (info.vendor[0] == '\0')
            {
                constexpr char fallbackVendor[] = "x64";
                std::memcpy(info.vendor, fallbackVendor, sizeof(fallbackVendor));
            }
            return info;
        }();
        return cached;
#else
        static const CpuRuntimeInfo cached = QueryCpuRuntimePortable();
        return cached;
#endif
    }

    bool CpuHasFeature(const CpuRuntimeInfo& info, CpuRuntimeFeatureFlags flag)
    {
        return (info.featureFlags & static_cast<std::uint64_t>(flag)) != 0;
    }

    std::string DescribeCpuFeatureFlags(const CpuRuntimeInfo& info)
    {
        std::vector<std::string> labels;
        if (CpuHasFeature(info, cpu_feature_x64))
            labels.emplace_back("x64");
        if (CpuHasFeature(info, cpu_feature_sse2))
            labels.emplace_back("sse2");
        if (CpuHasFeature(info, cpu_feature_sse3))
            labels.emplace_back("sse3");
        if (CpuHasFeature(info, cpu_feature_ssse3))
            labels.emplace_back("ssse3");
        if (CpuHasFeature(info, cpu_feature_sse41))
            labels.emplace_back("sse4.1");
        if (CpuHasFeature(info, cpu_feature_sse42))
            labels.emplace_back("sse4.2");
        if (CpuHasFeature(info, cpu_feature_popcnt))
            labels.emplace_back("popcnt");
        if (CpuHasFeature(info, cpu_feature_aesni))
            labels.emplace_back("aes-ni");
        if (CpuHasFeature(info, cpu_feature_xsave))
            labels.emplace_back("xsave");
        if (CpuHasFeature(info, cpu_feature_osxsave))
            labels.emplace_back("osxsave");
        if (CpuHasFeature(info, cpu_feature_avx))
            labels.emplace_back("avx");
        if (CpuHasFeature(info, cpu_feature_avx_os))
            labels.emplace_back("avx state");
        if (CpuHasFeature(info, cpu_feature_avx2))
            labels.emplace_back("avx2");
        if (CpuHasFeature(info, cpu_feature_bmi1))
            labels.emplace_back("bmi1");
        if (CpuHasFeature(info, cpu_feature_bmi2))
            labels.emplace_back("bmi2");
        if (CpuHasFeature(info, cpu_feature_sha))
            labels.emplace_back("sha");

        if (labels.empty())
            return "generic scalar fallback";

        std::ostringstream oss;
        for (std::size_t i = 0; i < labels.size(); ++i)
        {
            if (i > 0)
                oss << ", ";
            oss << labels[i];
        }
        return oss.str();
    }

    std::string DescribeCpuRuntime(const CpuRuntimeInfo& info)
    {
        const std::string vendor = TrimAsciiCopy(info.vendor);
        const std::string brand = TrimAsciiCopy(info.brand);

        std::ostringstream oss;
        oss << (!vendor.empty() ? vendor : std::string("unknown vendor"));
        if (!brand.empty())
            oss << " / " << brand;
        oss << " / " << DescribeCpuFeatureFlags(info);
        return oss.str();
    }

    LowLevelBufferProfile ProfileBufferLowLevel(const std::uint8_t* buffer, std::size_t size)
    {
#if defined(_MSC_VER) && defined(_M_X64)
        LowLevelBufferProfile profile;
        BL_ProfileBufferLowLevel_Asm(buffer, size, &profile);
        return profile;
#else
        return ProfileBufferLowLevelPortable(buffer, size);
#endif
    }

    void MergeBufferProfile(LowLevelBufferProfile& total, const LowLevelBufferProfile& chunk)
    {
        total.sampleBytes += chunk.sampleBytes;
        total.zeroByteCount += chunk.zeroByteCount;
        total.ffByteCount += chunk.ffByteCount;
        total.printableAsciiCount += chunk.printableAsciiCount;
        total.controlByteCount += chunk.controlByteCount;
        total.highByteCount += chunk.highByteCount;
        total.transitionCount += chunk.transitionCount;
        total.repeatedByteRunCount += chunk.repeatedByteRunCount;
        total.longestZeroRun = (std::max)(total.longestZeroRun, chunk.longestZeroRun);
        total.longestPrintableRun = (std::max)(total.longestPrintableRun, chunk.longestPrintableRun);
    }

    std::string DescribeBufferProfile(const LowLevelBufferProfile& profile)
    {
        if (profile.sampleBytes == 0)
            return {};

        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2)
            << "printable " << SafeRatio(profile.printableAsciiCount, profile.sampleBytes) * 100.0 << "%, "
            << "zero " << SafeRatio(profile.zeroByteCount, profile.sampleBytes) * 100.0 << "%, "
            << "high-byte " << SafeRatio(profile.highByteCount, profile.sampleBytes) * 100.0 << "%, "
            << "transitions " << SafeRatio(profile.transitionCount, profile.sampleBytes > 1 ? profile.sampleBytes - 1 : 1) * 100.0 << "%, "
            << "longest zero run " << profile.longestZeroRun << ", "
            << "longest printable run " << profile.longestPrintableRun;
        return oss.str();
    }

    AsciiTokenProfile ScanAsciiTokens(const std::uint8_t* buffer, std::size_t size)
    {
#if defined(_MSC_VER) && defined(_M_X64)
        AsciiTokenProfile profile;
        BL_ScanAsciiTokens_Asm(buffer, size, &profile);
        return profile;
#else
        return ScanAsciiTokensPortable(buffer, size);
#endif
    }

    void MergeAsciiTokenProfile(AsciiTokenProfile& total, const AsciiTokenProfile& chunk)
    {
        total.httpHits += chunk.httpHits;
        total.httpsHits += chunk.httpsHits;
        total.wwwHits += chunk.wwwHits;
        total.powershellHits += chunk.powershellHits;
        total.cmdExeHits += chunk.cmdExeHits;
        total.executableHits += chunk.executableHits;
        total.dynamicLibraryHits += chunk.dynamicLibraryHits;
        total.scriptExtensionHits += chunk.scriptExtensionHits;
        total.registryHits += chunk.registryHits;
        total.urlLikeHits += chunk.urlLikeHits;
        total.emailMarkerHits += chunk.emailMarkerHits;
        total.ipv4LikeHits += chunk.ipv4LikeHits;
    }

    std::vector<std::string> DescribeAsciiTokenSignals(const AsciiTokenProfile& profile)
    {
        std::vector<std::string> labels;
        if (profile.urlLikeHits > 0)
            labels.emplace_back("raw bytes exposed url-style prefixes " + std::to_string(profile.urlLikeHits) + " time(s)");
        if (profile.powershellHits > 0)
            labels.emplace_back("raw bytes exposed powershell tokens " + std::to_string(profile.powershellHits) + " time(s)");
        if (profile.cmdExeHits > 0)
            labels.emplace_back("raw bytes exposed cmd.exe tokens " + std::to_string(profile.cmdExeHits) + " time(s)");
        if (profile.executableHits > 0)
            labels.emplace_back("raw bytes exposed executable extension markers " + std::to_string(profile.executableHits) + " time(s)");
        if (profile.dynamicLibraryHits > 0)
            labels.emplace_back("raw bytes exposed dll extension markers " + std::to_string(profile.dynamicLibraryHits) + " time(s)");
        if (profile.scriptExtensionHits > 0)
            labels.emplace_back("raw bytes exposed script extension markers " + std::to_string(profile.scriptExtensionHits) + " time(s)");
        if (profile.registryHits > 0)
            labels.emplace_back("raw bytes exposed registry hive markers " + std::to_string(profile.registryHits) + " time(s)");
        if (profile.emailMarkerHits >= 2)
            labels.emplace_back("raw bytes contained repeated email-like separators");
        if (profile.ipv4LikeHits > 0)
            labels.emplace_back("raw bytes contained ipv4-like numeric patterns " + std::to_string(profile.ipv4LikeHits) + " time(s)");
        return labels;
    }

    CodeSurfaceProfile ProfileCodeSurface(const std::uint8_t* code, std::size_t size)
    {
#if defined(_MSC_VER) && defined(_M_X64)
        CodeSurfaceProfile profile;
        BL_ProfileCodeSurface_Asm(code, size, &profile);
        return profile;
#else
        return ProfileCodeSurfacePortable(code, size);
#endif
    }

    std::string DescribeCodeSurfaceProfile(const CodeSurfaceProfile& profile)
    {
        std::vector<std::string> labels;
        if (profile.branchOpcodeCount >= 3)
            labels.emplace_back("branch-dense opening window");
        if (profile.retOpcodeCount > 0)
            labels.emplace_back("early return opcode");
        if (profile.nopOpcodeCount >= 3)
            labels.emplace_back("nop padding");
        if (profile.int3OpcodeCount > 0)
            labels.emplace_back("int3 padding");
        if (profile.stackFrameHintCount > 0)
            labels.emplace_back("stack-frame setup");
        if (profile.ripRelativeHintCount > 0)
            labels.emplace_back("rip-relative data access");

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

    OpcodeFamilyProfile ProfileOpcodeFamilies(const std::uint8_t* code, std::size_t size)
    {
#if defined(_MSC_VER) && defined(_M_X64)
        OpcodeFamilyProfile profile;
        BL_ProfileOpcodeFamilies_Asm(code, size, &profile);
        return profile;
#else
        return ProfileOpcodeFamiliesPortable(code, size);
#endif
    }

    std::string DescribeOpcodeFamilyProfile(const OpcodeFamilyProfile& profile)
    {
        std::vector<std::string> labels;
        if (profile.controlTransferCount >= 5)
            labels.emplace_back("control-transfer heavy");
        if (profile.stackOperationCount >= 4)
            labels.emplace_back("stack-setup heavy");
        if (profile.memoryTouchCount >= 4)
            labels.emplace_back("memory-touch rich");
        if (profile.arithmeticLogicCount >= 5)
            labels.emplace_back("arithmetic or logic dense");
        if (profile.compareTestCount >= 3)
            labels.emplace_back("predicate-heavy");
        if (profile.loopLikeCount >= 2)
            labels.emplace_back("loop-oriented");
        if (profile.syscallInterruptCount > 0)
            labels.emplace_back("syscall or interrupt capable");
        if (profile.stringInstructionCount > 0)
            labels.emplace_back("string-instruction activity");

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

    AsmEntrypointProfile BuildEntrypointProfile(const std::uint8_t* code,
                                                          std::size_t size,
                                                          std::uint64_t sourceOffset)
    {
        AsmEntrypointProfile report;
        report.window.sourceOffset = sourceOffset;
        report.window.requestedBytes = static_cast<std::uint32_t>((std::min)(size, static_cast<std::size_t>(0xFFFFFFFFu)));
        report.window.observedBytes = report.window.requestedBytes;
        report.window.profiledBytes = static_cast<std::uint32_t>((std::min)(size, kEntrypointProfileWindowBytes));
        report.window.usedNativeBackend = IsAsmBackendAvailable();
        report.window.truncatedToWindow = size > kEntrypointProfileWindowBytes;

        if (!code || size == 0)
            return report;

        // all three profilers read the same caller-owned window so their outputs can be compared without drift.
        report.entryProfile = ProfileEntrypointStub(code, size);
        report.codeSurface = ProfileCodeSurface(code, size);
        report.opcodeFamilies = ProfileOpcodeFamilies(code, size);
        report.entrySummary = DescribeEntrypointProfile(report.entryProfile);
        report.codeSurfaceSummary = DescribeCodeSurfaceProfile(report.codeSurface);
        report.opcodeFamilySummary = DescribeOpcodeFamilyProfile(report.opcodeFamilies);

        // semantic tags stay downstream from the raw counters so later weighting can change without rewriting the asm layer.
        const OpcodeSemanticSummary semanticSummary = BuildOpcodeSemanticSummary(report.entryProfile,
                                                                                report.codeSurface,
                                                                                report.opcodeFamilies);
        report.tags = semanticSummary.tags;
        report.findings = semanticSummary.findings;
        report.suggestsStub = semanticSummary.stubLike || report.entryProfile.suspiciousOpcodeScore >= 4;
        report.suggestsLoader = semanticSummary.loaderLike;
        report.suggestsResolver = semanticSummary.resolverLike;
        report.suggestsDecoder = semanticSummary.decoderLike || HasFeature(report.entryProfile, stub_decoder_loop);

        AppendFeatureReason(report.entryProfile,
                            stub_initial_jump,
                            "ep.initial_jump",
                            "entrypoint profiling saw an immediate control-transfer opcode at the start of the window",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_push_ret,
                            "ep.push_ret",
                            "entrypoint profiling matched a push-ret transfer shape that often appears in short trampolines",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_call_pop,
                            "ep.call_pop",
                            "entrypoint profiling matched a call-pop resolver shape in the opening bytes",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_peb_access,
                            "ep.peb_access",
                            "entrypoint profiling matched teb-peb style access patterns in the profiled window",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_syscall_sequence,
                            "ep.syscall_sequence",
                            "entrypoint profiling observed a syscall-style opcode pair in the opening window",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_decoder_loop,
                            "ep.decoder_loop",
                            "entrypoint profiling observed a compact xor-or-write style loop that can support staged decoding",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_stack_pivot,
                            "ep.stack_pivot",
                            "entrypoint profiling observed a stack-pivot oriented opcode pattern",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_sparse_padding,
                            "ep.sparse_padding",
                            "entrypoint profiling saw dense padding bytes that make the opening window look stub-like",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_suspicious_branch_density,
                            "ep.branch_density",
                            "entrypoint profiling counted enough short control transfers to flag an unusually branch-dense opening window",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_manual_mapping_hint,
                            "ep.manual_mapping_hint",
                            "entrypoint profiling observed memory-access shapes that are compatible with manual-mapping style setup",
                            report);
        AppendFeatureReason(report.entryProfile,
                            stub_memory_walk_hint,
                            "ep.memory_walk_hint",
                            "entrypoint profiling observed memory-walk style instruction shapes early in the byte window",
                            report);

        if (report.codeSurface.branchOpcodeCount >= 3)
        {
            AddSignalKey(report.signals, "surface.branch_dense");
            AddReason(report.notes, "code-surface profiling counted a branch-dense opening window");
        }
        if (report.codeSurface.retOpcodeCount > 0)
        {
            AddSignalKey(report.signals, "surface.early_ret");
            AddReason(report.notes, "code-surface profiling saw a return opcode inside the short entrypoint window");
        }
        if (report.codeSurface.nopOpcodeCount >= 3)
        {
            AddSignalKey(report.signals, "surface.nop_padding");
            AddReason(report.notes, "code-surface profiling saw repeated nop bytes that look like deliberate padding");
        }
        if (report.codeSurface.int3OpcodeCount > 0)
        {
            AddSignalKey(report.signals, "surface.int3_padding");
            AddReason(report.notes, "code-surface profiling saw int3 bytes in the opening window");
        }
        if (report.codeSurface.stackFrameHintCount > 0)
        {
            AddSignalKey(report.signals, "surface.stack_frame_setup");
            AddReason(report.notes, "code-surface profiling saw stack-frame setup bytes in the opening window");
        }
        if (report.codeSurface.ripRelativeHintCount > 0)
        {
            AddSignalKey(report.signals, "surface.rip_relative");
            AddReason(report.notes, "code-surface profiling saw rip-relative addressing in the opening window");
        }

        if (report.opcodeFamilies.controlTransferCount >= 5)
            AddSignalKey(report.signals, "family.control_transfer_heavy");
        if (report.opcodeFamilies.stackOperationCount >= 4)
            AddSignalKey(report.signals, "family.stack_heavy");
        if (report.opcodeFamilies.memoryTouchCount >= 4)
            AddSignalKey(report.signals, "family.memory_touch_rich");
        if (report.opcodeFamilies.arithmeticLogicCount >= 5)
            AddSignalKey(report.signals, "family.arithmetic_logic_dense");
        if (report.opcodeFamilies.compareTestCount >= 3)
            AddSignalKey(report.signals, "family.compare_test_dense");
        if (report.opcodeFamilies.loopLikeCount >= 2)
            AddSignalKey(report.signals, "family.loop_oriented");
        if (report.opcodeFamilies.syscallInterruptCount > 0)
            AddSignalKey(report.signals, "family.syscall_capable");
        if (report.opcodeFamilies.stringInstructionCount > 0)
            AddSignalKey(report.signals, "family.string_activity");

        for (const std::string& tag : report.tags)
            AddSignalKey(report.signals, "semantic." + tag);

        // the reasoning trail is intentionally plain-language because it is meant for logs, reports, and json diffs.
        if (!report.entrySummary.empty())
            AddReason(report.notes, "entrypoint summary: " + report.entrySummary);
        if (!report.codeSurfaceSummary.empty())
            AddReason(report.notes, "code-surface summary: " + report.codeSurfaceSummary);
        if (!report.opcodeFamilySummary.empty())
            AddReason(report.notes, "opcode-family summary: " + report.opcodeFamilySummary);

        if (!report.entrySummary.empty())
            bl::common::AddUnique(report.findings, "entrypoint profile suggests " + report.entrySummary, 16);
        if (!report.codeSurfaceSummary.empty())
            bl::common::AddUnique(report.findings, "code surface suggests " + report.codeSurfaceSummary, 16);
        if (!report.opcodeFamilySummary.empty())
            bl::common::AddUnique(report.findings, "opcode families suggest " + report.opcodeFamilySummary, 16);

        return report;
    }

    std::string DescribeProfilingWindow(const AsmProfilingWindow& window)
    {
        std::ostringstream oss;
        oss << "offset " << window.sourceOffset
            << ", observed " << window.observedBytes << " byte(s)"
            << ", profiled " << window.profiledBytes << " byte(s)"
            << ", backend " << (window.usedNativeBackend ? "native x64 asm" : "portable c++ fallback");
        if (window.truncatedToWindow)
            oss << ", truncated to schema window";
        return oss.str();
    }

    std::string DescribeEntrypointSignals(const AsmEntrypointProfile& report)
    {
        return JoinLabels(report.signals);
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
