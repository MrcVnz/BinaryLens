#include "analyzers/embedded_payload_analyzer.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <vector>

#include "asm/asm_bridge.h"

namespace
{
    constexpr std::size_t kMaxScanBytes = 512u * 1024u;
    constexpr std::size_t kShellcodeWindow = 64u;
    constexpr std::size_t kShellcodeStep = 16u;
    constexpr std::size_t kMinimumEmbeddedOffset = 64u;
    constexpr std::size_t kMinimumMaskedCorroborationOffset = 96u;

    std::string ToLowerCopy(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    void AddFinding(EmbeddedPayloadAnalysisResult& result, const std::string& finding, unsigned int scoreBoost)
    {
        if (std::find(result.findings.begin(), result.findings.end(), finding) == result.findings.end())
            result.findings.push_back(finding);
        result.score += scoreBoost;
    }

    void AddUniqueDetail(std::vector<std::string>& target, const std::string& value)
    {
        if (value.empty())
            return;
        if (std::find(target.begin(), target.end(), value) == target.end())
            target.push_back(value);
    }

    void AddContextNote(EmbeddedPayloadAnalysisResult& result, const std::string& value)
    {
        AddUniqueDetail(result.contextualNotes, value);
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

    double ComputeHighBitRatio(const std::uint8_t* data, std::size_t size)
    {
        if (data == nullptr || size == 0)
            return 0.0;

        std::size_t highBitCount = 0;
        for (std::size_t i = 0; i < size; ++i)
        {
            if ((data[i] & 0x80u) != 0)
                ++highBitCount;
        }
        return static_cast<double>(highBitCount) / static_cast<double>(size);
    }

    bool LooksLikeValidatedEmbeddedPE(const std::vector<std::uint8_t>& data, std::size_t offset)
    {
        // do not trust a naked mz marker by itself; require a plausible pe signature layout too.
        if (offset + 0x40 >= data.size())
            return false;
        if (data[offset] != 'M' || data[offset + 1] != 'Z')
            return false;

        const std::uint32_t eLfanew = static_cast<std::uint32_t>(data[offset + 0x3C]) |
                                      (static_cast<std::uint32_t>(data[offset + 0x3D]) << 8) |
                                      (static_cast<std::uint32_t>(data[offset + 0x3E]) << 16) |
                                      (static_cast<std::uint32_t>(data[offset + 0x3F]) << 24);
        if (eLfanew < 0x40 || eLfanew > 0x1000)
            return false;
        if (offset + static_cast<std::size_t>(eLfanew) + 4 >= data.size())
            return false;

        const std::size_t peOffset = offset + static_cast<std::size_t>(eLfanew);
        if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
            return false;

        return true;
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
        if (!scan.found || scan.firstMatchOffset < kMinimumMaskedCorroborationOffset)
            return;

        AddUniqueDetail(result.maskedPatternFindings,
                        finding + " at offset " + std::to_string(static_cast<unsigned long long>(scan.firstMatchOffset)));
        AddFinding(result, finding, scoreBoost);
    }

    // only the leading chunk is needed for embedded blob triage.
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

    // suspicious names help catch delivery archives that hide behind common decoy themes.
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

    bool ArchiveInventoryLooksClean(const FileInfo& info)
    {
        if (!info.archiveInspectionPerformed)
            return false;
        return !info.archiveContainsExecutable &&
               !info.archiveContainsScript &&
               !info.archiveContainsShortcut &&
               !info.archiveContainsNestedArchive &&
               !info.archiveContainsPathTraversal &&
               !info.archiveContainsSuspiciousDoubleExtension &&
               !info.archiveContainsLureAndExecutablePattern &&
               info.zipSuspiciousEntryCount == 0;
    }

    void FinalizeDisposition(EmbeddedPayloadAnalysisResult& result, const FileInfo& info)
    {
        const bool archiveClean = ArchiveInventoryLooksClean(info);
        const bool hasMaskedMotifs = !result.maskedPatternFindings.empty();
        result.corroborationCount = 0;
        if (result.foundEmbeddedPE)
            ++result.corroborationCount;
        if (result.foundExecutableArchiveLure)
            ++result.corroborationCount;
        if (result.foundShellcodeLikeBlob)
            ++result.corroborationCount;
        if (hasMaskedMotifs)
            ++result.corroborationCount;
        if (result.strongestMemoryAccessPatternCount > 0)
            ++result.corroborationCount;

        result.payloadCorroborated = result.corroborationCount >= 2 &&
                                     (result.foundEmbeddedPE || result.foundExecutableArchiveLure || result.strongestMemoryAccessPatternCount > 0);

        // compressed archives can easily imitate low-level opcode motifs, so keep that context explicit.
        if (!result.payloadCorroborated && archiveClean && info.isZipArchive && result.strongestHighBitRatio >= 0.45)
        {
            result.likelyCompressedNoise = true;
            AddContextNote(result, "archive/container data likely explains part of the raw opcode motif surface");
        }

        if (result.payloadCorroborated)
        {
            result.signalReliability = result.corroborationCount >= 4 ? "High" : "Moderate";
            result.disposition = result.foundEmbeddedPE
                ? "Corroborated staged payload indicators"
                : "Corroborated low-level execution motif cluster";
        }
        else if (result.foundShellcodeLikeBlob || hasMaskedMotifs || result.suspiciousWindowCount >= 3)
        {
            result.signalReliability = archiveClean ? "Low" : "Moderate";
            result.disposition = result.likelyCompressedNoise
                ? "Low-confidence low-level motifs inside compressed/container data"
                : "Low-confidence without payload corroboration";
        }
        else
        {
            result.signalReliability = "Low";
            result.disposition = "No corroborated embedded payload signal";
        }

        if (archiveClean)
            AddContextNote(result, "archive inventory looked clean and did not expose executable, script, or lure entries");
        if (!result.payloadCorroborated && result.strongestProfileSummary.empty() && !result.maskedPatternFindings.empty())
            AddContextNote(result, "masked motifs were observed without a strong raw-code profile in the sampled region");
    }
}

EmbeddedPayloadAnalysisResult AnalyzeEmbeddedPayloads(const std::string& filePath, const FileInfo& info)
{
    EmbeddedPayloadAnalysisResult result;
    // keep this pass cheap by limiting the read size.
    const std::vector<std::uint8_t> data = ReadLeadingBytes(filePath, kMaxScanBytes);
    if (data.empty())
        return result;

    result.analyzed = true;
    result.usedNativeAsmBackend = bl::asmbridge::IsAsmBackendAvailable();

    // search for secondary mz markers, but only keep them when the pe signature layout is plausible too.
    if (!info.isPELike)
    {
        for (std::size_t i = kMinimumEmbeddedOffset; i + 1 < data.size(); ++i)
        {
            if (data[i] == 'M' && data[i + 1] == 'Z' && LooksLikeValidatedEmbeddedPE(data, i))
            {
                result.foundEmbeddedPE = true;
                result.embeddedPEOffset = i;
                AddFinding(result, "validated embedded portable executable header detected inside a non-pe sample", 14);
                break;
            }
        }
    }

    // profile sliding raw-code windows so shellcode-like stubs can be surfaced outside the pe entrypoint path.
    for (std::size_t i = 0; i + kShellcodeWindow <= data.size(); i += kShellcodeStep)
    {
        const std::uint8_t first = data[i];
        const bool plausibleCodeLead = first == 0xE8 || first == 0xE9 || first == 0xEB || first == 0x55 ||
                                       first == 0x48 || first == 0x4C || first == 0x60 || first == 0x90 || first == 0xFC;
        if (!plausibleCodeLead)
            continue;

        const auto profile = bl::asmbridge::ProfileEntrypointStub(data.data() + i, kShellcodeWindow);
        if (profile.suspiciousOpcodeScore >= 5)
        {
            ++result.suspiciousWindowCount;
            if (profile.suspiciousOpcodeScore > result.strongestOpcodeScore)
            {
                // retain the strongest raw-code window so the report can show why the payload triage escalated.
                result.strongestOpcodeScore = profile.suspiciousOpcodeScore;
                result.strongestBranchOpcodeCount = profile.branchOpcodeCount;
                result.strongestMemoryAccessPatternCount = profile.memoryAccessPatternCount;
                result.strongestProfileOffset = i;
                result.strongestProfileSummary = bl::asmbridge::DescribeEntrypointProfile(profile);
                result.strongestProfileDetails = BuildAsmProfileDetails(profile);
                result.strongestHighBitRatio = ComputeHighBitRatio(data.data() + i, kShellcodeWindow);
            }
        }

        const bool strongProfile = profile.suspiciousOpcodeScore >= 8 &&
                                   (profile.branchOpcodeCount >= 2 || profile.memoryAccessPatternCount >= 1);
        if (strongProfile)
        {
            result.foundShellcodeLikeBlob = true;
            result.shellcodeOffset = i;
            AddFinding(result, "shellcode-like raw code window detected outside the normal pe entrypoint path", 12);

            if (result.strongestProfileSummary.empty())
                result.strongestProfileSummary = bl::asmbridge::DescribeEntrypointProfile(profile);
            if (result.strongestProfileDetails.empty())
                result.strongestProfileDetails = BuildAsmProfileDetails(profile);
            if (result.strongestHighBitRatio <= 0.0)
                result.strongestHighBitRatio = ComputeHighBitRatio(data.data() + i, kShellcodeWindow);

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
                                   3);
        TryAddMaskedPatternFinding(result,
                                   data,
                                   callPopPattern,
                                   "x????x",
                                   sizeof(callPopPattern),
                                   "masked opcode scan located a call-pop style resolver pattern",
                                   3);
        TryAddMaskedPatternFinding(result,
                                   data,
                                   syscallPattern,
                                   "xx",
                                   sizeof(syscallPattern),
                                   "masked opcode scan located a syscall-style sequence in raw bytes",
                                   2);
        TryAddMaskedPatternFinding(result,
                                   data,
                                   pebPattern,
                                   "xxx",
                                   sizeof(pebPattern),
                                   "masked opcode scan located a peb-oriented access sequence",
                                   2);
    }

    if (!result.foundShellcodeLikeBlob && result.suspiciousWindowCount >= 3)
    {
        AddFinding(result, "multiple suspicious raw code windows were clustered in the sampled file region", 4);
    }

    if ((info.isZipArchive && info.archiveContainsExecutable) || LooksLikeExecutableLure(info))
    {
        result.foundExecutableArchiveLure = true;
        AddFinding(result, "embedded delivery or lure pattern suggests executable staging behavior", 8);
    }

    FinalizeDisposition(result, info);

    // do the final score trim here so the main engine can consume a more honest signal.
    if (!result.payloadCorroborated)
    {
        if (result.likelyCompressedNoise)
            result.score = std::min(result.score, 8u);
        else
            result.score = std::min(result.score, 14u);
    }

    return result;
}
