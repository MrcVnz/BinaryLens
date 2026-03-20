
#include "core/evasion_engine.h"

#include <algorithm>
// evasion signal correlation for anti-analysis, stealth, and staging patterns.

// utility logic for anti-analysis, stealth, and environment-aware execution signals.
namespace
{
    void AddFinding(EvasionAnalysisResult& out, const std::string& finding, int boost)
    {
        if (std::find(out.findings.begin(), out.findings.end(), finding) == out.findings.end())
            out.findings.push_back(finding);
        out.scoreBoost += boost;
    }

    std::string ToLowerCopy(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    bool LooksLikeInstallerOrBootstrapper(const FileInfo& info, const Indicators& indicators)
    {
        const std::string nameLower = ToLowerCopy(info.name);
        const std::string pathLower = ToLowerCopy(info.path);
        return indicators.hasInstallerTraits ||
               nameLower.find("setup") != std::string::npos ||
               nameLower.find("installer") != std::string::npos ||
               pathLower.find("bootstrap") != std::string::npos ||
               pathLower.find("visualstudio") != std::string::npos;
    }
}

// aggregates evasion evidence across imports, pe layout, indicators, and simulated behavior.
EvasionAnalysisResult AnalyzeEvasionSignals(const FileInfo& info, const PEAnalysisResult& peInfo, const ImportAnalysisResult& importInfo, const Indicators& indicators)
{
    EvasionAnalysisResult out;
    // bootstrapper-like samples get softer weighting to avoid overcalling common installers.
    const bool installerLike = LooksLikeInstallerOrBootstrapper(info, indicators);
    if (peInfo.hasAntiDebugIndicators && peInfo.antiDebugIndicatorCount >= 3)
        AddFinding(out, "Anti-debug API cluster detected", installerLike ? 2 : 6);

    // combine layout, entropy, and sparse imports before treating packing as meaningful.
    const bool strongPackedSignal = peInfo.possiblePackedFile &&
        (peInfo.highEntropyExecutableSectionCount > 0 || peInfo.writableExecutableSectionCount > 0 || importInfo.totalImports <= 20);
    if (strongPackedSignal || (info.entropy >= 7.2 && importInfo.totalImports > 0 && importInfo.totalImports <= 20))
        AddFinding(out, installerLike ? "Compressed bootstrapper-style executable layout detected" : "Possible packed or compressed executable layout", installerLike ? 2 : 8);

    if (indicators.hasEvasionTraits && indicators.evasionEvidenceCount >= 2)
        AddFinding(out, "String indicators reference sandbox or debugger awareness", installerLike ? 2 : 5);
    if (info.readable && info.entropy >= 7.4 && indicators.asciiStringCount < 24 && info.extension == ".exe")
        AddFinding(out, "Low printable-string density with high entropy suggests obfuscation", installerLike ? 3 : 7);
    if (peInfo.hasEntrypointJumpStub && peInfo.highEntropyExecutableSectionCount > 0)
        AddFinding(out, "Entrypoint trampoline combined with high-entropy executable section", installerLike ? 2 : 5);
    if (info.archiveInspectionPerformed && info.archiveContainsNestedArchive)
        AddFinding(out, "Nested archive structure can be used to evade simple scanning", 4);
    return out;
}
