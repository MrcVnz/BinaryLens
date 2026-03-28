#include "analyzers/embedded_payload_analyzer.h"
#include "common/string_utils.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <vector>

#include "asm/asm_bridge.h"

namespace
{
    constexpr std::size_t kMaxScanBytes = 512u * 1024u;
    constexpr std::size_t kShellcodeWindow = 64u;
    constexpr std::size_t kShellcodeStep = 16u;
    constexpr std::size_t kMinimumEmbeddedOffset = 64u;
    constexpr std::size_t kEmbeddedPeProximityWindow = 512u;

    struct ByteWindowMetrics
    {
        double printableRatio = 0.0;
        double highBitRatio = 0.0;
        double zeroRatio = 0.0;
        double opcodeLeadRatio = 0.0;
    };

    std::string ToLowerCopy(std::string value)
    {
        return bl::common::ToLowerCopy(std::move(value));
    }

    void AddFinding(EmbeddedPayloadAnalysisResult& result, const std::string& finding, unsigned int scoreBoost)
    {
        if (std::find(result.findings.begin(), result.findings.end(), finding) == result.findings.end())
            result.findings.push_back(finding);
        result.score += scoreBoost;
    }

    void AddUniqueDetail(std::vector<std::string>& target, const std::string& value)
    {
        bl::common::AddUnique(target, value, 16);
    }

    void AddContextNote(EmbeddedPayloadAnalysisResult& result, const std::string& value)
    {
        bl::common::AddUnique(result.contextNotes, value, 10);
    }

    std::vector<std::string> BuildAsmProfileDetails(const bl::asmbridge::EntrypointAsmProfile& profile)
    {
        std::vector<std::string> details;

        // keep the shellcode profile notes terse so they fit both gui reports and analyst pivots.
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_initial_jump))
            details.push_back("early control transfer detected in raw code window");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_push_ret))
            details.push_back("push-ret redirection pattern detected in raw code window");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_call_pop))
            details.push_back("call-pop resolver pattern detected in raw code window");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_peb_access))
            details.push_back("peb-oriented access pattern detected in raw code window");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_syscall_sequence))
            details.push_back("syscall-style opcode sequence detected in raw code window");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_decoder_loop))
            details.push_back("decoder-like opcode loop detected in raw code window");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_stack_pivot))
            details.push_back("stack-pivot style opcode pattern detected in raw code window");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_sparse_padding))
            details.push_back("sparse padding density suggests staged stub layout");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_suspicious_branch_density))
            details.push_back("branch density is elevated in the strongest raw code window");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_manual_mapping_hint))
            details.push_back("manual-mapping style traversal pattern detected in raw code window");
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_memory_walk_hint))
            details.push_back("memory-walk style opcode pattern detected in raw code window");

        return details;
    }

    std::uint32_t ReadLe32(const std::vector<std::uint8_t>& data, std::size_t offset)
    {
        return static_cast<std::uint32_t>(data[offset]) |
               (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
               (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
               (static_cast<std::uint32_t>(data[offset + 3]) << 24);
    }

    std::uint16_t ReadLe16(const std::vector<std::uint8_t>& data, std::size_t offset)
    {
        return static_cast<std::uint16_t>(data[offset]) |
               (static_cast<std::uint16_t>(data[offset + 1]) << 8);
    }

    bool LooksLikeValidEmbeddedPeAtOffset(const std::vector<std::uint8_t>& data, std::size_t offset)
    {
        if (offset + 0x40 >= data.size())
            return false;
        if (data[offset] != 'M' || data[offset + 1] != 'Z')
            return false;

        const std::uint32_t e_lfanew = ReadLe32(data, offset + 0x3C);
        if (e_lfanew > 1024u * 1024u)
            return false;
        const std::size_t peOffset = offset + static_cast<std::size_t>(e_lfanew);
        if (peOffset + 0x18 >= data.size())
            return false;
        if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
            return false;

        const std::uint16_t machine = ReadLe16(data, peOffset + 4);
        const std::uint16_t numberOfSections = ReadLe16(data, peOffset + 6);
        const std::uint16_t optionalMagic = ReadLe16(data, peOffset + 0x18);
        if (numberOfSections == 0 || numberOfSections > 64)
            return false;
        if (optionalMagic != 0x10Bu && optionalMagic != 0x20Bu)
            return false;
        switch (machine)
        {
        case 0x14Cu:
        case 0x8664u:
        case 0x1C4u:
        case 0xAA64u:
            return true;
        default:
            return false;
        }
    }

    ByteWindowMetrics MeasureWindow(const std::uint8_t* window, std::size_t size)
    {
        static const std::array<std::uint8_t, 18> opcodeLeads = { 0xE8, 0xE9, 0xEB, 0x55, 0x48, 0x4C, 0x60, 0x90, 0xFC, 0x68, 0x58, 0x65, 0x8B, 0x8D, 0x89, 0x83, 0x31, 0x33 };
        ByteWindowMetrics metrics;
        if (!window || size == 0)
            return metrics;

        std::size_t printable = 0;
        std::size_t highBit = 0;
        std::size_t zero = 0;
        std::size_t opcodeLeadCount = 0;
        for (std::size_t i = 0; i < size; ++i)
        {
            const std::uint8_t value = window[i];
            if ((value >= 32 && value <= 126) || value == '\r' || value == '\n' || value == '\t')
                ++printable;
            if (value & 0x80)
                ++highBit;
            if (value == 0)
                ++zero;
            if (std::find(opcodeLeads.begin(), opcodeLeads.end(), value) != opcodeLeads.end())
                ++opcodeLeadCount;
        }

        metrics.printableRatio = static_cast<double>(printable) / static_cast<double>(size);
        metrics.highBitRatio = static_cast<double>(highBit) / static_cast<double>(size);
        metrics.zeroRatio = static_cast<double>(zero) / static_cast<double>(size);
        metrics.opcodeLeadRatio = static_cast<double>(opcodeLeadCount) / static_cast<double>(size);
        return metrics;
    }

    bool LooksCompressedLikeWindow(const ByteWindowMetrics& metrics)
    {
        return metrics.printableRatio < 0.10 &&
               metrics.zeroRatio < 0.08 &&
               metrics.highBitRatio > 0.45 &&
               metrics.opcodeLeadRatio < 0.18;
    }

    bool LooksLikeExecutableLure(const FileInfo& info)
    {
        if (!info.doubleExtensionSuspicious)
            return false;
        const std::string lower = ToLowerCopy(info.name);
        return lower.find("invoice") != std::string::npos ||
               lower.find("payment") != std::string::npos ||
               lower.find("document") != std::string::npos ||
               lower.find("scan") != std::string::npos ||
               lower.find("resume") != std::string::npos;
    }

    std::vector<std::uint8_t> ReadLeadingBytes(const std::string& filePath, std::size_t maxBytes)
    {
        std::ifstream file(filePath, std::ios::binary);
        if (!file)
            return {};

        std::vector<std::uint8_t> data(maxBytes, 0);
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        data.resize(static_cast<std::size_t>(file.gcount()));
        return data;
    }

    int ComputeWindowQuality(const bl::asmbridge::EntrypointAsmProfile& profile,
                             const ByteWindowMetrics& metrics,
                             bool nearValidatedEmbeddedPe,
                             bool compressedLike)
    {
        int quality = static_cast<int>(profile.suspiciousOpcodeScore) * 3;
        quality += static_cast<int>(profile.branchOpcodeCount) * 2;
        quality += static_cast<int>(profile.memoryAccessPatternCount) * 3;
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_decoder_loop))
            quality += 4;
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_peb_access))
            quality += 5;
        if (bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_call_pop) || bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_push_ret))
            quality += 3;
        if (nearValidatedEmbeddedPe)
            quality += 5;
        quality += static_cast<int>(metrics.opcodeLeadRatio * 10.0);
        if (compressedLike)
            quality -= 8;
        return quality;
    }

    void TryAddMaskedPatternFinding(EmbeddedPayloadAnalysisResult& result,
                                    const std::vector<std::uint8_t>& data,
                                    const std::uint8_t* pattern,
                                    const char* mask,
                                    std::size_t patternSize,
                                    const std::string& finding,
                                    unsigned int scoreBoost)
    {
        const auto scan = bl::asmbridge::FindPatternMasked(data.data(), data.size(), pattern, mask, patternSize);
        if (!scan.found || scan.firstMatchOffset < kMinimumEmbeddedOffset)
            return;

        AddUniqueDetail(result.maskedPatternFindings,
                        finding + " at offset " + std::to_string(static_cast<unsigned long long>(scan.firstMatchOffset)));
        AddFinding(result, finding, scoreBoost);
    }
}

// this pass treats raw-byte reversing signals as probabilistic evidence, not automatic truth, especially inside container formats.
EmbeddedPayloadAnalysisResult AnalyzeEmbeddedPayloads(const std::string& filePath, const FileInfo& info)
{
    EmbeddedPayloadAnalysisResult result;
    const std::vector<std::uint8_t> data = ReadLeadingBytes(filePath, kMaxScanBytes);
    if (data.empty())
        return result;

    result.analyzed = true;
    result.usedNativeAsmBackend = bl::asmbridge::IsAsmBackendAvailable();

    // embedded mz markers are only escalated when a downstream pe header layout is still structurally plausible.
    if (!info.isPELike)
    {
        bool sawLooseMzMarker = false;
        for (std::size_t i = kMinimumEmbeddedOffset; i + 1 < data.size(); ++i)
        {
            if (data[i] != 'M' || data[i + 1] != 'Z')
                continue;

            sawLooseMzMarker = true;
            if (!LooksLikeValidEmbeddedPeAtOffset(data, i))
                continue;

            ++result.validatedPeCandidateCount;
            if (!result.foundEmbeddedPE)
            {
                result.foundEmbeddedPE = true;
                result.validatedEmbeddedPE = true;
                result.embeddedPEOffset = i;
                AddFinding(result, "structurally valid embedded portable executable header detected inside a non-pe sample", 22);
            }
        }

        if (!result.foundEmbeddedPE && sawLooseMzMarker)
            AddContextNote(result, "raw mz-like markers were present, but the surrounding bytes did not form a consistent pe header layout");
    }

    int strongestQuality = -999;

    // sliding window profiling stays, but now it scores execution plausibility and compression noise separately.
    for (std::size_t i = 0; i + kShellcodeWindow <= data.size(); i += kShellcodeStep)
    {
        const std::uint8_t first = data[i];
        const bool plausibleCodeLead = first == 0xE8 || first == 0xE9 || first == 0xEB || first == 0x55 ||
                                       first == 0x48 || first == 0x4C || first == 0x60 || first == 0x90 || first == 0xFC ||
                                       first == 0x68 || first == 0x65 || first == 0x31 || first == 0x33;
        if (!plausibleCodeLead)
            continue;

        const auto profile = bl::asmbridge::ProfileEntrypointStub(data.data() + i, kShellcodeWindow);
        if (profile.suspiciousOpcodeScore < 5)
            continue;

        ++result.suspiciousWindowCount;
        const ByteWindowMetrics metrics = MeasureWindow(data.data() + i, kShellcodeWindow);
        const bool compressedLike = LooksCompressedLikeWindow(metrics);
        if (compressedLike)
            ++result.compressedLikeWindowCount;

        const bool nearValidatedEmbeddedPe = result.foundEmbeddedPE &&
            i >= result.embeddedPEOffset &&
            (i - result.embeddedPEOffset) <= kEmbeddedPeProximityWindow;
        const int quality = ComputeWindowQuality(profile, metrics, nearValidatedEmbeddedPe, compressedLike);

        if (quality > strongestQuality)
        {
            strongestQuality = quality;
            result.strongestOpcodeScore = profile.suspiciousOpcodeScore;
            result.strongestBranchOpcodeCount = profile.branchOpcodeCount;
            result.strongestMemoryAccessPatternCount = profile.memoryAccessPatternCount;
            result.strongestProfileOffset = i;
            result.strongestProfileSummary = bl::asmbridge::DescribeEntrypointProfile(profile);
            result.strongestProfileDetails = BuildAsmProfileDetails(profile);
            result.strongestWindowPrintableRatio = metrics.printableRatio;
            result.strongestWindowHighBitRatio = metrics.highBitRatio;
            result.strongestWindowZeroByteRatio = metrics.zeroRatio;
            result.strongestWindowOpcodeLeadRatio = metrics.opcodeLeadRatio;
        }

        const bool featureCorroboration =
            bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_decoder_loop) ||
            bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_peb_access) ||
            bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_call_pop) ||
            bl::asmbridge::HasFeature(profile, bl::asmbridge::stub_push_ret) ||
            profile.memoryAccessPatternCount >= 1;

        int shellcodeThreshold = info.archiveInspectionPerformed &&
                                 !info.archiveContainsExecutable &&
                                 !info.archiveContainsScript &&
                                 !info.archiveContainsShortcut
            ? 32
            : 26;
        if (result.foundEmbeddedPE)
            shellcodeThreshold -= 4;

        if (!compressedLike && quality >= shellcodeThreshold && (profile.branchOpcodeCount >= 2 || featureCorroboration))
        {
            result.foundShellcodeLikeBlob = true;
            result.shellcodeOffset = i;
            ++result.corroboratedWindowCount;
            AddFinding(result, "shellcode-like raw code window detected outside the normal pe entrypoint path", 18);
            break;
        }
    }

    // the masked scans intentionally look for common loader-shellcode motifs that benefit from the asm matcher.
    if (!info.isPELike || result.foundShellcodeLikeBlob || result.foundEmbeddedPE)
    {
        static const std::uint8_t pushRetPattern[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 };
        static const std::uint8_t callPopPattern[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 };
        static const std::uint8_t syscallPattern[] = { 0x0F, 0x05 };
        static const std::uint8_t pebPattern[] = { 0x65, 0x48, 0x8B };

        TryAddMaskedPatternFinding(result,
                                   data,
                                   pushRetPattern,
                                   "x????x",
                                   sizeof(pushRetPattern),
                                   "masked opcode scan located a push-ret style loader stub pattern",
                                   6);
        TryAddMaskedPatternFinding(result,
                                   data,
                                   callPopPattern,
                                   "x????x",
                                   sizeof(callPopPattern),
                                   "masked opcode scan located a call-pop style resolver pattern",
                                   6);
        TryAddMaskedPatternFinding(result,
                                   data,
                                   syscallPattern,
                                   "xx",
                                   sizeof(syscallPattern),
                                   "masked opcode scan located a syscall-style sequence in raw bytes",
                                   4);
        TryAddMaskedPatternFinding(result,
                                   data,
                                   pebPattern,
                                   "xxx",
                                   sizeof(pebPattern),
                                   "masked opcode scan located a peb-oriented access sequence",
                                   4);
    }

    if (LooksLikeExecutableLure(info))
    {
        result.foundExecutableArchiveLure = true;
        AddFinding(result, "suspicious executable lure naming detected in the outer container", 8);
    }

    result.strongCorroboration =
        (result.foundEmbeddedPE && result.foundShellcodeLikeBlob) ||
        (result.foundShellcodeLikeBlob && result.maskedPatternFindings.size() >= 2) ||
        (result.validatedPeCandidateCount > 0 && result.corroboratedWindowCount > 0);

    if (result.compressedLikeWindowCount > 0 && result.suspiciousWindowCount > 0 && result.compressedLikeWindowCount * 2 >= result.suspiciousWindowCount)
    {
        result.likelyCompressedNoise = true;
        AddContextNote(result, "many suspicious raw-code windows overlap compressed-looking byte distribution, which lowers shellcode confidence");
    }

    if (result.foundEmbeddedPE && result.validatedPeCandidateCount > 1)
        AddContextNote(result, "multiple structurally valid embedded pe candidates were observed in the sampled region");
    if (result.strongestWindowPrintableRatio > 0.45)
        AddContextNote(result, "the strongest raw-code window still contains a notable amount of printable data, which can happen in scripted or packed containers");
    if (result.strongestWindowHighBitRatio > 0.50 && result.strongestWindowZeroByteRatio < 0.05)
        AddContextNote(result, "the strongest raw-code window has a high compressed-byte bias and very few zero bytes");

    if (result.strongCorroboration)
    {
        result.signalReliability = "High";
        AddContextNote(result, "multiple independent low-level features agree on the staged payload interpretation");
        result.score += 6;
    }
    else if (result.foundEmbeddedPE || result.foundShellcodeLikeBlob)
    {
        result.signalReliability = result.likelyCompressedNoise ? "Low" : "Medium";
    }
    else if (result.suspiciousWindowCount >= 3 || !result.maskedPatternFindings.empty())
    {
        result.signalReliability = result.likelyCompressedNoise ? "Low" : "Medium";
    }

    if (result.likelyCompressedNoise)
    {
        result.score = result.score > 12 ? result.score - 12 : 0;
        AddContextNote(result, "compressed-container characteristics reduced the embedded payload score to avoid overcalling archive noise");
    }

    return result;
}
