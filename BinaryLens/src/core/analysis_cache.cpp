#include "core/analysis_cache.h"

#include "common/runtime_paths.h"
#include "core/analysis_engine.h"
#include "scanners/file_scanner.h"
#include "third_party/json.hpp"

#include <fstream>

// cache persistence keeps repeated scans cheap without changing the analysis result itself.

namespace
{
    // bump these together whenever report shape or cache assumptions change.
    constexpr int kAnalysisCacheSchemaVersion = 3;
    constexpr char kAnalysisCacheFormatTag[] = "report-v3";

    // sha256 is the stable cache key because it survives renames and path moves.
    std::filesystem::path GetCachePathForSha(const std::string& sha256)
    // collects the get cache path for sha data for this analysis cache step before higher level code consumes it.
    {
        if (sha256.empty())
            return {};
        return bl::common::GetAnalysisCacheDirectory() / (sha256 + ".json");
    }
}

// cache reads stay defensive because stale or partial files are cheaper to ignore than to trust.
bool TryLoadAnalysisCache(const FileInfo& info, AnalysisReportData& cachedReport)
// keeps cache handling local so the rest of the pipeline does not need storage details.
{
    const std::filesystem::path cachePath = GetCachePathForSha(info.sha256);
    if (cachePath.empty())
        return false;

    std::ifstream in(cachePath, std::ios::binary);
    if (!in)
        return false;

    try
    {
        // parsing happens directly from disk because cache payloads are small and already json-shaped.
        nlohmann::json parsed;
        in >> parsed;

        // every guard below makes sure we only reuse output from the same engine shape and the same sample.
        if (parsed.value("schema_version", 0) != kAnalysisCacheSchemaVersion)
            return false;
        if (parsed.value("format_tag", std::string()) != kAnalysisCacheFormatTag)
            return false;
        if (parsed.value("source_size", 0ull) != info.size)
            return false;
        if (parsed.value("sha256", std::string()) != info.sha256)
            return false;

        // every view is restored independently so partial cache payloads can still be reused safely.
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

// writes are best-effort because cache failure should never fail the analysis itself.
void SaveAnalysisCache(const FileInfo& info, const AnalysisReportData& reportData)
// keeps cache handling local so the rest of the pipeline does not need storage details.
{
    const std::filesystem::path cachePath = GetCachePathForSha(info.sha256);
    if (cachePath.empty())
        return;

    try
    {
        // cache writes preserve all exported views so the ui can reopen any one of them instantly.
        nlohmann::json payload;
        payload["schema_version"] = kAnalysisCacheSchemaVersion;
        payload["format_tag"] = kAnalysisCacheFormatTag;
        payload["sha256"] = info.sha256;
        payload["source_size"] = info.size;
        payload["user_view"] = reportData.textReport;
        payload["analyst_view"] = reportData.analystTextReport;
        payload["ioc_view"] = reportData.iocTextReport;
        payload["json_report"] = reportData.jsonReport;

        // truncate first so partially updated cache payloads do not keep old trailing bytes around.
        std::ofstream out(cachePath, std::ios::binary | std::ios::trunc);
        if (!out)
            return;

        out << payload.dump(2);
    }
    catch (...)
    {
    }
}
