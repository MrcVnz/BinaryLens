#include "core/analysis_cache.h"

#include "common/runtime_paths.h"
#include "core/analysis_engine.h"
#include "scanners/file_scanner.h"
#include "third_party/json.hpp"

#include <fstream>

namespace
{
    constexpr int kAnalysisCacheSchemaVersion = 2;

    std::filesystem::path GetCachePathForSha(const std::string& sha256)
    {
        if (sha256.empty())
            return {};
        return bl::common::GetAnalysisCacheDirectory() / (sha256 + ".json");
    }
}

bool TryLoadAnalysisCache(const FileInfo& info, AnalysisReportData& cachedReport)
{
    const std::filesystem::path cachePath = GetCachePathForSha(info.sha256);
    if (cachePath.empty())
        return false;

    std::ifstream in(cachePath, std::ios::binary);
    if (!in)
        return false;

    try
    {
        nlohmann::json parsed;
        in >> parsed;

        if (parsed.value("schema_version", 0) != kAnalysisCacheSchemaVersion)
            return false;
        if (parsed.value("source_size", 0ull) != info.size)
            return false;
        if (parsed.value("sha256", std::string()) != info.sha256)
            return false;

        cachedReport.textReport = parsed.value("user_view", std::string());
        cachedReport.analystTextReport = parsed.value("analyst_view", std::string());
        cachedReport.iocTextReport = parsed.value("ioc_view", std::string());
        cachedReport.jsonReport = parsed.value("json_report", std::string());
        return !cachedReport.textReport.empty() || !cachedReport.analystTextReport.empty() || !cachedReport.jsonReport.empty();
    }
    catch (...)
    {
        return false;
    }
}

void SaveAnalysisCache(const FileInfo& info, const AnalysisReportData& reportData)
{
    const std::filesystem::path cachePath = GetCachePathForSha(info.sha256);
    if (cachePath.empty())
        return;

    try
    {
        nlohmann::json payload;
        payload["schema_version"] = kAnalysisCacheSchemaVersion;
        payload["sha256"] = info.sha256;
        payload["source_size"] = info.size;
        payload["user_view"] = reportData.textReport;
        payload["analyst_view"] = reportData.analystTextReport;
        payload["ioc_view"] = reportData.iocTextReport;
        payload["json_report"] = reportData.jsonReport;

        std::ofstream out(cachePath, std::ios::binary | std::ios::trunc);
        if (!out)
            return;

        out << payload.dump(2);
    }
    catch (...)
    {
    }
}
