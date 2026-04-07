#pragma once

// contextual scoring calibration that separates strong reverse-engineering evidence from noisy container artifacts.
#include <string>
#include <vector>

#include "analyzers/embedded_payload_analyzer.h"
#include "analyzers/import_analyzer.h"
#include "analyzers/indicator_extractor.h"
#include "analyzers/pe_analyzer.h"
#include "scanners/file_scanner.h"
#include "services/api_client.h"
#include "services/signature_checker.h"

struct EvidenceCalibrationResult
{
    int riskDelta = 0;
    bool preferCautiousEmbeddedNarrative = false;
    bool preferEscalatedEmbeddedNarrative = false;
    std::string embeddedPayloadDisposition;
    std::string lowLevelSummary;
    std::vector<std::string> calibrationNotes;
    std::vector<std::string> legitimateContext;
    std::vector<std::string> correlationHighlights;
    std::vector<std::string> confidenceNotes;
    std::vector<std::string> userFacingHighlights;
    std::vector<std::string> lowLevelNotes;
};

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
                                                   bool likelyLegitimateBootstrapper);
