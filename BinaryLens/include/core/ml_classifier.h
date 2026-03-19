#pragma once

// lightweight classifier outputs used as an auxiliary signal in the final verdict.
#include <string>
#include <vector>

#include "analyzers/import_analyzer.h"
#include "analyzers/indicator_extractor.h"
#include "analyzers/pe_analyzer.h"
#include "scanners/file_scanner.h"
#include "services/signature_checker.h"

struct MlAssessmentResult
{
    std::string label = "Benign-leaning";
    std::string confidence = "Low";
    int score = 0;
    std::vector<std::string> featureNotes;
};

MlAssessmentResult RunLightweightMlAssessment(const FileInfo& info,
                                              const PEAnalysisResult& peInfo,
                                              const ImportAnalysisResult& importInfo,
                                              const Indicators& indicators,
                                              const SignatureCheckResult& sigInfo);
