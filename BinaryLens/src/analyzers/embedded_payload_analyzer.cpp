#include "analyzers/embedded_payload_analyzer.h"

#include <algorithm>
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

    // searches for secondary mz signatures past the natural file header to catch wrapped or embedded pe blobs.
    if (!info.isPELike)
    {
        for (std::size_t i = kMinimumEmbeddedOffset; i + 1 < data.size(); ++i)
        {
            if (data[i] == 'M' && data[i + 1] == 'Z')
            {
                result.foundEmbeddedPE = true;
                result.embeddedPEOffset = i;
                AddFinding(result, "embedded portable executable header detected inside a non-pe sample", 20);
                break;
            }
        }
    }

    // profiles sliding raw-code windows so shellcode-like stubs can be surfaced outside the pe entrypoint path.
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
            }
        }

        if (profile.suspiciousOpcodeScore >= 8 &&
            (profile.branchOpcodeCount >= 2 || profile.memoryAccessPatternCount >= 1))
        {
            result.foundShellcodeLikeBlob = true;
            result.shellcodeOffset = i;
            AddFinding(result, "shellcode-like raw code window detected outside the normal pe entrypoint path", 18);

            if (result.strongestProfileSummary.empty())
                result.strongestProfileSummary = bl::asmbridge::DescribeEntrypointProfile(profile);
            if (result.strongestProfileDetails.empty())
                result.strongestProfileDetails = BuildAsmProfileDetails(profile);

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

    if (!result.foundShellcodeLikeBlob && result.suspiciousWindowCount >= 3)
    {
        AddFinding(result, "multiple suspicious raw code windows were clustered in the sampled file region", 8);
    }

    if ((info.isZipArchive && info.archiveContainsExecutable) || LooksLikeExecutableLure(info))
    {
        result.foundExecutableArchiveLure = true;
        AddFinding(result, "embedded delivery or lure pattern suggests executable staging behavior", 8);
    }

    return result;
}
