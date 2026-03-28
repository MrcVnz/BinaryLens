#pragma once

// mitre attack mapping helpers derived from correlated static capability signals.
#include <string>
#include <vector>

struct FileInfo;
struct Indicators;
struct ImportAnalysisResult;
struct PEAnalysisResult;

std::vector<std::string> BuildMitreTechniqueLabels(const FileInfo& info,
                                                   const Indicators& indicators,
                                                   const ImportAnalysisResult& importInfo,
                                                   const PEAnalysisResult& peInfo);
