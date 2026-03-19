#pragma once

// top-level orchestration entry points for file and url analysis workflows.
#include <cstdint>
#include <functional>
#include <string>

struct AnalysisProgress
{
    std::string mode;
    std::string stage;
    std::string detail;
    std::uint64_t processedBytes = 0;
    std::uint64_t totalBytes = 0;
    std::uint64_t chunkIndex = 0;
    std::uint64_t chunkCount = 0;
    double speedMBps = 0.0;
    int etaSeconds = -1;
    int percent = 0;
    bool heavyFileMode = false;
    bool cancellationRequested = false;
};

using AnalysisProgressCallback = std::function<void(const AnalysisProgress&)>;

struct AnalysisReportData
{
    std::string textReport;
    std::string analystTextReport;
    std::string iocTextReport;
    std::string jsonReport;
};

AnalysisReportData RunUrlAnalysisDetailed(const std::string& inputURL);
AnalysisReportData RunFileAnalysisDetailed(const std::string& filePath, AnalysisProgressCallback progressCallback = nullptr);
std::string RunUrlAnalysis(const std::string& inputURL);
std::string RunFileAnalysis(const std::string& filePath, AnalysisProgressCallback progressCallback = nullptr);
