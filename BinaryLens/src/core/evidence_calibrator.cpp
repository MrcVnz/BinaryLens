#include "core/evidence_calibrator.h"
#include "common/string_utils.h"

#include <algorithm>

namespace
{
    void AddUnique(std::vector<std::string>& out, const std::string& value, std::size_t maxCount = 12)
    {
        bl::common::AddUnique(out, value, maxCount);
    }

    bool HasCluster(const ImportAnalysisResult& importInfo, const std::string& cluster)
    {
        return std::find(importInfo.capabilityClusters.begin(), importInfo.capabilityClusters.end(), cluster) != importInfo.capabilityClusters.end();
    }

    bool HasExecutionCorroboration(const ImportAnalysisResult& importInfo, const Indicators& indicators)
    {
        return indicators.hasInjectionTraits ||
               indicators.hasDownloaderTraits ||
               indicators.hasPersistenceTraits ||
               indicators.hasCredentialTheftTraits ||
               indicators.hasRansomwareTraits ||
               HasCluster(importInfo, "Process Injection") ||
               HasCluster(importInfo, "Dynamic API Resolution") ||
               HasCluster(importInfo, "Network Beaconing / C2") ||
               HasCluster(importInfo, "Persistence") ||
               HasCluster(importInfo, "Discovery / Secret Access");
    }

    bool HasTag(const std::vector<std::string>& tags, const std::string& tag)
    {
        return std::find(tags.begin(), tags.end(), tag) != tags.end();
    }

    bool ArchiveInventoryLooksClean(const FileInfo& info)
    {
        return info.archiveInspectionPerformed &&
               !info.archiveContainsExecutable &&
               !info.archiveContainsScript &&
               !info.archiveContainsShortcut &&
               !info.archiveContainsPathTraversal &&
               !info.archiveContainsLureAndExecutablePattern &&
               !info.archiveContainsSuspiciousDoubleExtension &&
               info.zipSuspiciousEntryCount == 0;
    }

    bool ReputationLooksClean(bool hasReputation, const ReputationResult& reputation)
    {
        return hasReputation &&
               reputation.success &&
               reputation.maliciousDetections == 0 &&
               reputation.suspiciousDetections == 0;
    }
}

// this pass keeps low-level reversing signals useful without letting compressed containers or trusted installers snowball the score.
EvidenceCalibrationResult BuildEvidenceCalibration(const FileInfo& info,
                                                   const PEAnalysisResult& peInfo,
                                                   const ImportAnalysisResult& importInfo,
                                                   const Indicators& indicators,
                                                   const EmbeddedPayloadAnalysisResult& embeddedPayloadInfo,
                                                   const SignatureCheckResult& sigInfo,
                                                   bool hasYaraMatches,
                                                   bool hasPluginMatches,
                                                   bool hasReputation,
                                                   const ReputationResult& reputation,
                                                   bool trustedPublisher,
                                                   bool trustedSignedPe,
                                                   bool likelyLegitimateBootstrapper)
{
    EvidenceCalibrationResult out;

    const bool archiveInventoryClean = ArchiveInventoryLooksClean(info);
    const bool cleanReputation = ReputationLooksClean(hasReputation, reputation);
    const bool executionCorroboration = HasExecutionCorroboration(importInfo, indicators);
    const bool lowLevelOnlyPressure = (embeddedPayloadInfo.foundEmbeddedPE ||
                                       embeddedPayloadInfo.foundShellcodeLikeBlob ||
                                       !embeddedPayloadInfo.maskedPatternFindings.empty()) &&
                                      !executionCorroboration &&
                                      !hasYaraMatches &&
                                      !hasPluginMatches;

    if (archiveInventoryClean && lowLevelOnlyPressure)
    {
        out.preferCautiousEmbeddedNarrative = true;
        out.embeddedPayloadDisposition = embeddedPayloadInfo.likelyCompressedNoise
            ? "Low-confidence in compressed archive context"
            : "Low-confidence without payload corroboration";

        out.riskDelta -= embeddedPayloadInfo.likelyCompressedNoise ? 18 : 12;
        if (cleanReputation)
            out.riskDelta -= 6;

        AddUnique(out.calibrationNotes, "Archive inventory looked clean even though low-level raw-byte heuristics fired", 8);
        AddUnique(out.legitimateContext, "Archive deep inspection did not reveal executable, script, shortcut, or traversal payloads", 8);
        AddUnique(out.legitimateContext, "Raw-byte findings occurred inside a containerized sample where compressed data can mimic opcode motifs", 8);
        if (cleanReputation)
            AddUnique(out.legitimateContext, "Reputation did not corroborate the raw-byte findings", 8);
        AddUnique(out.confidenceNotes, "Embedded payload heuristics were not backed by archive payload evidence", 8);
        AddUnique(out.userFacingHighlights, "Container context reduced the weight of shellcode-like byte motifs", 8);
    }

    const bool stagedArchivePath = info.archiveInspectionPerformed &&
        (info.archiveContainsExecutable || info.archiveContainsScript || info.archiveContainsShortcut || info.archiveContainsLureAndExecutablePattern);
    if (stagedArchivePath && embeddedPayloadInfo.strongCorroboration)
    {
        out.preferEscalatedEmbeddedNarrative = true;
        out.embeddedPayloadDisposition = "High-confidence staged payload path";
        out.riskDelta += 10;
        AddUnique(out.correlationHighlights, "Archive delivery indicators line up with corroborated embedded payload traits", 8);
        AddUnique(out.calibrationNotes, "Embedded payload heuristics aligned with suspicious archive inventory", 8);
        AddUnique(out.userFacingHighlights, "Archive and payload heuristics reinforce each other", 8);
    }

    const bool overlayLooksInstallerCompatible = peInfo.overlayWindowCount > 0 &&
        (peInfo.overlayTextWindowCount > 0 || peInfo.overlayUrlWindowCount > 0 || peInfo.overlayEmbeddedHeaderHits > 0);
    const bool ambiguousSignedBootstrapper = likelyLegitimateBootstrapper &&
        trustedSignedPe &&
        embeddedPayloadInfo.foundShellcodeLikeBlob &&
        !embeddedPayloadInfo.strongCorroboration &&
        !hasYaraMatches &&
        !executionCorroboration;
    if (ambiguousSignedBootstrapper)
    {
        out.preferCautiousEmbeddedNarrative = true;
        if (out.embeddedPayloadDisposition.empty())
            out.embeddedPayloadDisposition = "Ambiguous bootstrapper-style low-level signal";
        out.riskDelta -= 10;
        if (cleanReputation)
            out.riskDelta -= 4;
        AddUnique(out.legitimateContext, "Trusted signed bootstrapper context can explain loader-like byte patterns", 8);
        AddUnique(out.confidenceNotes, "Trusted signer and installer context compete with the low-level heuristics", 8);
    }

    // signed installers commonly carry overlays, url-bearing metadata, and short bootstrap stubs without crossing into malicious execution.
    if (likelyLegitimateBootstrapper && trustedSignedPe && overlayLooksInstallerCompatible && !hasYaraMatches && !executionCorroboration)
    {
        out.riskDelta -= 6;
        AddUnique(out.legitimateContext, "Overlay profile looks compatible with a staged installer or bootstrapper layout", 8);
        AddUnique(out.legitimateContext, "Overlay carried text, url, or embedded-header regions that fit installer packaging", 8);
        AddUnique(out.confidenceNotes, "Installer-compatible overlay structure lowered the weight of ambiguous loader telemetry", 8);
    }

    if (trustedSignedPe && likelyLegitimateBootstrapper && (HasTag(peInfo.asmSemanticTags, "stub-like") || HasTag(peInfo.asmSemanticTags, "loader-like")) && !executionCorroboration && !hasYaraMatches)
    {
        out.riskDelta -= 4;
        AddUnique(out.legitimateContext, "Entrypoint semantics look bootstrap-oriented, but the signer and installer context remain strong", 8);
        AddUnique(out.calibrationNotes, "Low-level entrypoint semantics were retained as telemetry instead of being treated as dominant risk", 8);
    }

    if (embeddedPayloadInfo.strongCorroboration && executionCorroboration)
    {
        if (out.embeddedPayloadDisposition.empty())
            out.embeddedPayloadDisposition = "Corroborated low-level execution path";
        out.preferEscalatedEmbeddedNarrative = true;
        out.riskDelta += 8;
        AddUnique(out.correlationHighlights, "Low-level opcode evidence aligns with higher-level behavioral indicators", 8);
    }

    if (embeddedPayloadInfo.validatedEmbeddedPE && indicators.hasDownloaderTraits && !cleanReputation)
    {
        out.riskDelta += 6;
        AddUnique(out.correlationHighlights, "Downloader indicators align with a structurally valid embedded PE candidate", 8);
    }

    if (trustedPublisher && sigInfo.signatureValid && info.archiveInspectionPerformed && archiveInventoryClean && embeddedPayloadInfo.likelyCompressedNoise)
    {
        out.riskDelta -= 4;
        AddUnique(out.legitimateContext, "Trusted context plus compressed-archive characteristics reduced confidence in raw-byte hits", 8);
    }

    return out;
}
