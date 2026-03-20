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
        if (profile.suspiciousOpcodeScore >= 8 &&
            (profile.branchOpcodeCount >= 2 || profile.memoryAccessPatternCount >= 1))
        {
            result.foundShellcodeLikeBlob = true;
            result.shellcodeOffset = i;
            AddFinding(result, "shellcode-like raw code window detected outside the normal pe entrypoint path", 18);
            break;
        }
    }

    if ((info.isZipArchive && info.archiveContainsExecutable) || LooksLikeExecutableLure(info))
    {
        result.foundExecutableArchiveLure = true;
        AddFinding(result, "embedded delivery or lure pattern suggests executable staging behavior", 8);
    }

    return result;
}
