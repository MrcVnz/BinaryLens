#include "core/ml_classifier.h"

#include <algorithm>
// feature based classifier stub that contributes an auxiliary probabilistic signal.

// feature preparation helpers for the lightweight classifier path.
namespace
{
    void AddNote(MlAssessmentResult& out, const std::string& value)
    {
        if (value.empty())
            return;
        if (std::find(out.featureNotes.begin(), out.featureNotes.end(), value) == out.featureNotes.end())
            out.featureNotes.push_back(value);
    }
}

// this is a rule-backed placeholder so the output can expose an ml lane without bluffing.
MlAssessmentResult RunLightweightMlAssessment(const FileInfo& info, const PEAnalysisResult& peInfo, const ImportAnalysisResult& importInfo, const Indicators& indicators, const SignatureCheckResult& sigInfo)
{
    MlAssessmentResult out;

    if (info.isPELike) { out.score += 8; AddNote(out, "Portable executable feature present"); }
    if (info.entropy >= 7.4) { out.score += 8; AddNote(out, "High entropy feature"); }
    if (peInfo.hasOverlay && peInfo.overlaySize > 1024 * 1024) { out.score += 7; AddNote(out, "Large overlay feature"); }
    if (peInfo.highEntropyExecutableSectionCount > 0) { out.score += 10; AddNote(out, "High-entropy executable section feature"); }
    if (peInfo.writableExecutableSectionCount > 0) { out.score += 10; AddNote(out, "Writable executable section feature"); }
    if (indicators.hasDownloaderTraits) { out.score += 10; AddNote(out, "Downloader trait feature"); }
    if (indicators.hasInjectionTraits) { out.score += 12; AddNote(out, "Injection trait feature"); }
    if (indicators.hasRansomwareTraits) { out.score += 14; AddNote(out, "Ransomware trait feature"); }
    if (indicators.hasCredentialTheftTraits) { out.score += 10; AddNote(out, "Credential access feature"); }
    if (importInfo.suspiciousImportCount >= 6) { out.score += 8; AddNote(out, "Dense suspicious import feature"); }

    if (sigInfo.isSigned && sigInfo.signatureValid)
    {
        out.score -= 16;
        AddNote(out, "Valid signature reduces model score");
    }

    if (out.score >= 45)
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

    return out;
}
