#pragma once

// behavior simulation structures that summarize likely execution intent from static evidence.
#include <string>
#include <vector>

struct FileInfo;
struct Indicators;
struct ImportAnalysisResult;
struct PEAnalysisResult;

struct SimulatedBehaviorReport
{
    std::vector<std::string> behaviors;
    std::vector<std::string> analystNotes;
    std::vector<std::string> timelineSteps;
};

SimulatedBehaviorReport BuildSimulatedBehaviorReport(const FileInfo& info, const Indicators& indicators, const ImportAnalysisResult& importInfo, const PEAnalysisResult& peInfo);
