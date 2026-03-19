
#pragma once

#include <string>
#include <vector>

#include "analyzers/import_analyzer.h"
#include "analyzers/indicator_extractor.h"
#include "analyzers/pe_analyzer.h"
#include "scanners/file_scanner.h"
// evasion-focused correlation outputs derived from pe, string, and context signals.

struct EvasionAnalysisResult
{
    std::vector<std::string> findings;
    int scoreBoost = 0;
};

EvasionAnalysisResult AnalyzeEvasionSignals(const FileInfo& info,
                                            const PEAnalysisResult& peInfo,
                                            const ImportAnalysisResult& importInfo,
                                            const Indicators& indicators);
