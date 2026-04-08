#include "core/ml_classifier.h"
#include "common/string_utils.h"

// feature based classifier stub that contributes an auxiliary probabilistic signal.

namespace
{
    // feature notes explain the lightweight score without pretending this is a standalone model.
    void AddNote(MlAssessmentResult& out, const std::string& value)
    // adds this detail through one gate so duplicate or noisy output stays under control.
    {
        bl::common::AddUnique(out.featureNotes, value, 12);
    }
}

// this remains a heuristic fusion lane, but now exposes clearer confidence bands and stronger context reductions.
// this remains a heuristic fusion lane, but now exposes clearer confidence bands and stronger context reductions.
MlAssessmentResult RunLightweightMlAssessment(const FileInfo& info, const PEAnalysisResult& peInfo, const ImportAnalysisResult& importInfo, const Indicators& indicators, const SignatureCheckResult& sigInfo)
// keeps the run lightweight ml assessment step local to this lightweight ml scoring file so callers can stay focused on intent.
{
    MlAssessmentResult out;

    // feature weights stay intentionally modest because the result is only one lane in the final decision.
    if (info.isPELike) { out.score += 8; AddNote(out, "Portable executable feature present"); }
    if (info.entropy >= 7.4) { out.score += 8; AddNote(out, "High entropy feature"); }
    if (peInfo.hasOverlay && peInfo.overlaySize > 1024 * 1024) { out.score += 7; AddNote(out, "Large overlay feature"); }
    if (peInfo.highEntropyExecutableSectionCount > 0) { out.score += 10; AddNote(out, "High-entropy executable section feature"); }
    if (peInfo.writableExecutableSectionCount > 0) { out.score += 10; AddNote(out, "Writable executable section feature"); }
    if (indicators.hasDownloaderTraits) { out.score += 10; AddNote(out, "Downloader trait feature"); }
    if (indicators.hasInjectionTraits) { out.score += 14; AddNote(out, "Injection trait feature"); }
    if (indicators.hasRansomwareTraits) { out.score += 16; AddNote(out, "Ransomware trait feature"); }
    if (indicators.hasCredentialTheftTraits) { out.score += 12; AddNote(out, "Credential access feature"); }
    if (importInfo.suspiciousImportCount >= 6) { out.score += 8; AddNote(out, "Dense suspicious import feature"); }
    if (std::find(importInfo.capabilityClusters.begin(), importInfo.capabilityClusters.end(), "Dynamic API Resolution") != importInfo.capabilityClusters.end())
    {
        out.score += 6;
        AddNote(out, "Dynamic api resolution feature");
    }

    // installer context is reused later as a reduction because setup stubs can look hostile in isolation.
    const bool installerLike = indicators.hasInstallerTraits || bl::common::ToLowerCopy(info.name).find("setup") != std::string::npos ||
                               bl::common::ToLowerCopy(info.name).find("installer") != std::string::npos;

    // signature reduction is strong on purpose because signed installers are a common false-positive source.
    if (sigInfo.isSigned && sigInfo.signatureValid)
    {
        out.score -= installerLike ? 18 : 16;
        AddNote(out, "Valid signature reduces model score");
    }

    // installer context gets its own reduction because many vendors ship compressed bootstrap stubs.
    if (installerLike)
    {
        out.score -= 6;
        AddNote(out, "Installer-like context reduced score pressure");
    }

    // the output bands stay broad so small score swings do not flip labels too aggressively.
    // these bands are intentionally broad because the lightweight classifier is only advisory.
    if (out.score >= 62)
    {
        out.label = "Malicious-leaning";
        out.confidence = "High";
    }
    else if (out.score >= 42)
    {
        out.label = "Malicious-leaning";
        out.confidence = "Medium";
    }
    else if (out.score >= 22)
    {
        out.label = "Suspicious-leaning";
        out.confidence = "Medium";
    }
    else
    {
        out.label = "Benign-leaning";
        out.confidence = "Low";
    }

    // callers treat this as one advisory lane, not as a standalone verdict.
    return out;
}
