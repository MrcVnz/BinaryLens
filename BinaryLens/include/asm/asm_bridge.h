#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

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

    enum CpuRuntimeFeatureFlags : std::uint64_t
    {
        cpu_feature_sse2 = 1ull << 0,
        cpu_feature_sse3 = 1ull << 1,
        cpu_feature_ssse3 = 1ull << 2,
        cpu_feature_sse41 = 1ull << 3,
        cpu_feature_sse42 = 1ull << 4,
        cpu_feature_avx = 1ull << 5,
        cpu_feature_avx2 = 1ull << 6,
        cpu_feature_bmi1 = 1ull << 7,
        cpu_feature_bmi2 = 1ull << 8,
        cpu_feature_aesni = 1ull << 9,
        cpu_feature_sha = 1ull << 10,
        cpu_feature_popcnt = 1ull << 11,
        cpu_feature_x64 = 1ull << 12,
        cpu_feature_xsave = 1ull << 13,
        cpu_feature_osxsave = 1ull << 14,
        cpu_feature_avx_os = 1ull << 15
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

    struct CpuRuntimeInfo
    {
        char vendor[16] = {};
        char brand[64] = {};
        std::uint32_t maxBasicLeaf = 0;
        std::uint32_t maxExtendedLeaf = 0;
        std::uint64_t featureFlags = 0;
    };

    struct LowLevelBufferProfile
    {
        std::uint64_t sampleBytes = 0;
        std::uint64_t zeroByteCount = 0;
        std::uint64_t ffByteCount = 0;
        std::uint64_t printableAsciiCount = 0;
        std::uint64_t controlByteCount = 0;
        std::uint64_t highByteCount = 0;
        std::uint64_t transitionCount = 0;
        std::uint64_t repeatedByteRunCount = 0;
        std::uint64_t longestZeroRun = 0;
        std::uint64_t longestPrintableRun = 0;
    };

    struct AsciiTokenProfile
    {
        std::uint32_t httpHits = 0;
        std::uint32_t httpsHits = 0;
        std::uint32_t wwwHits = 0;
        std::uint32_t powershellHits = 0;
        std::uint32_t cmdExeHits = 0;
        std::uint32_t executableHits = 0;
        std::uint32_t dynamicLibraryHits = 0;
        std::uint32_t scriptExtensionHits = 0;
        std::uint32_t registryHits = 0;
        std::uint32_t urlLikeHits = 0;
        std::uint32_t emailMarkerHits = 0;
        std::uint32_t ipv4LikeHits = 0;
    };

    struct CodeSurfaceProfile
    {
        std::uint32_t branchOpcodeCount = 0;
        std::uint32_t retOpcodeCount = 0;
        std::uint32_t nopOpcodeCount = 0;
        std::uint32_t int3OpcodeCount = 0;
        std::uint32_t stackFrameHintCount = 0;
        std::uint32_t ripRelativeHintCount = 0;
    };

    bool IsAsmBackendAvailable();

    PatternScanResult FindPatternMasked(const std::uint8_t* buffer,
                                        std::size_t bufferSize,
                                        const std::uint8_t* pattern,
                                        const char* mask,
                                        std::size_t patternSize);

    EntrypointAsmProfile ProfileEntrypointStub(const std::uint8_t* code, std::size_t size);

    CpuRuntimeInfo QueryCpuRuntimeInfo();
    bool CpuHasFeature(const CpuRuntimeInfo& info, CpuRuntimeFeatureFlags flag);
    std::string DescribeCpuRuntime(const CpuRuntimeInfo& info);
    std::string DescribeCpuFeatureFlags(const CpuRuntimeInfo& info);

    LowLevelBufferProfile ProfileBufferLowLevel(const std::uint8_t* buffer, std::size_t size);
    void MergeBufferProfile(LowLevelBufferProfile& total, const LowLevelBufferProfile& chunk);
    std::string DescribeBufferProfile(const LowLevelBufferProfile& profile);

    AsciiTokenProfile ScanAsciiTokens(const std::uint8_t* buffer, std::size_t size);
    void MergeAsciiTokenProfile(AsciiTokenProfile& total, const AsciiTokenProfile& chunk);
    std::vector<std::string> DescribeAsciiTokenSignals(const AsciiTokenProfile& profile);

    CodeSurfaceProfile ProfileCodeSurface(const std::uint8_t* code, std::size_t size);
    std::string DescribeCodeSurfaceProfile(const CodeSurfaceProfile& profile);

    bool HasFeature(const EntrypointAsmProfile& profile, StubFeatureFlags flag);
    std::string DescribeEntrypointProfile(const EntrypointAsmProfile& profile);
}
