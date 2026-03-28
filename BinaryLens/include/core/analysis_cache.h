#pragma once

// local analysis cache keyed by sha-256 to avoid recomputing the same report repeatedly.
#include <string>

struct FileInfo;
struct AnalysisReportData;

bool TryLoadAnalysisCache(const FileInfo& info, AnalysisReportData& cachedReport);
void SaveAnalysisCache(const FileInfo& info, const AnalysisReportData& reportData);
