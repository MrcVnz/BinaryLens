#include "services/api_client.h"
#include "common/runtime_paths.h"
#include "third_party/json.hpp"

#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using json = nlohmann::json;

namespace
{
    constexpr int kResolveTimeoutMs = 6000;
    constexpr int kConnectTimeoutMs = 6000;
    constexpr int kSendTimeoutMs = 10000;
    constexpr int kReceiveTimeoutMs = 15000;
    constexpr std::size_t kMaxHttpBodyBytes = 1024u * 1024u;

    struct HttpResponse
    {
        int statusCode = 0;
        std::string body;
    };

    std::wstring Utf8ToWide(const std::string& input)
    {
        return bl::common::Utf8ToWideCopy(input);
    }

    std::string ReadEnvVar(const char* name)
    {
        if (!name || !*name)
            return "";

        char buffer[8192] = {};
        const DWORD length = GetEnvironmentVariableA(name, buffer, static_cast<DWORD>(sizeof(buffer)));
        if (length == 0 || length >= sizeof(buffer))
            return "";
        return std::string(buffer, buffer + length);
    }

    std::string ReadKeyFromFile(const std::filesystem::path& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
            return "";

        try
        {
            json config;
            file >> config;

            if (config.contains("virustotal_api_key") && config["virustotal_api_key"].is_string())
                return config["virustotal_api_key"].get<std::string>();
            if (config.contains("api_key") && config["api_key"].is_string())
                return config["api_key"].get<std::string>();
        }
        catch (...)
        {
        }

        return "";
    }

    bool ApplyWinHttpHardening(HINTERNET hSession, HINTERNET hRequest)
    {
        if (hSession)
        {
            if (!WinHttpSetTimeouts(hSession, kResolveTimeoutMs, kConnectTimeoutMs, kSendTimeoutMs, kReceiveTimeoutMs))
                return false;
        }

        if (hRequest)
        {
            DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy)))
                return false;

            DWORD decompression = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
            WinHttpSetOption(hRequest, WINHTTP_OPTION_DECOMPRESSION, &decompression, sizeof(decompression));
        }

        return true;
    }

    bool CopyConfigIfMissing(const std::filesystem::path& sourcePath, const std::filesystem::path& destinationPath)
    {
        std::error_code ec;
        if (std::filesystem::exists(destinationPath, ec))
            return true;

        if (!std::filesystem::exists(sourcePath, ec) || !std::filesystem::is_regular_file(sourcePath, ec))
            return false;

        bl::common::EnsureDirectoryPath(destinationPath.parent_path());
        std::filesystem::copy_file(sourcePath, destinationPath, std::filesystem::copy_options::overwrite_existing, ec);
        return !ec;
    }

    HttpResponse PerformVirusTotalGet(const std::wstring& path, const std::string& apiKey)
    {
        HttpResponse response;
        if (apiKey.empty())
            return response;

        HINTERNET hSession = WinHttpOpen(L"BinaryLens/0.7", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
            return response;

        HINTERNET hConnect = WinHttpConnect(hSession, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return response;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return response;
        }

        if (!ApplyWinHttpHardening(hSession, hRequest))
        {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return response;
        }

        const std::wstring apiHeader = L"x-apikey: " + Utf8ToWide(apiKey);
        WinHttpAddRequestHeaders(hRequest, apiHeader.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

        BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (ok)
            ok = WinHttpReceiveResponse(hRequest, nullptr);

        if (ok)
        {
            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            if (WinHttpQueryHeaders(hRequest,
                                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX,
                                    &statusCode,
                                    &statusCodeSize,
                                    WINHTTP_NO_HEADER_INDEX))
            {
                response.statusCode = static_cast<int>(statusCode);
            }

            for (;;)
            {
                DWORD availableSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &availableSize) || availableSize == 0)
                    break;

                if (response.body.size() >= kMaxHttpBodyBytes)
                    break;

                const std::size_t chunkBudget = kMaxHttpBodyBytes - response.body.size();
                const DWORD chunkSize = static_cast<DWORD>(std::min<std::size_t>(chunkBudget, static_cast<std::size_t>(availableSize)));
                if (chunkSize == 0)
                    break;

                std::string buffer(chunkSize, '\0');
                DWORD bytesRead = 0;
                if (!WinHttpReadData(hRequest, buffer.data(), chunkSize, &bytesRead) || bytesRead == 0)
                    break;

                response.body.append(buffer.data(), bytesRead);
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    void FillStatsFromJson(const json& parsed, ReputationResult& result)
    {
        if (!parsed.contains("data") || !parsed["data"].is_object())
            return;
        const auto& data = parsed["data"];
        if (!data.contains("attributes") || !data["attributes"].is_object())
            return;
        const auto& attributes = data["attributes"];
        if (!attributes.contains("last_analysis_stats") || !attributes["last_analysis_stats"].is_object())
            return;
        const auto& stats = attributes["last_analysis_stats"];

        result.maliciousDetections = stats.value("malicious", 0);
        result.suspiciousDetections = stats.value("suspicious", 0);
        result.harmlessDetections = stats.value("harmless", 0);
        result.undetectedDetections = stats.value("undetected", 0);
    }

    void FinalizeFromHttpResponse(const HttpResponse& response, ReputationResult& result, const std::string& successSummary, const std::string& notFoundSummary)
    {
        result.httpStatusCode = response.statusCode;
        result.rawResponse = response.body;

        if (response.statusCode == 200)
        {
            try
            {
                const json parsed = json::parse(response.body);
                FillStatsFromJson(parsed, result);
                result.success = true;
                result.summary = successSummary;
                return;
            }
            catch (...) {}
        }

        if (response.statusCode == 404)
        {
            result.summary = notFoundSummary;
            return;
        }

        try
        {
            const json parsed = json::parse(response.body);
            if (parsed.contains("error") && parsed["error"].is_object())
            {
                const auto& error = parsed["error"];
                if (error.contains("message") && error["message"].is_string())
                {
                    result.summary = error["message"].get<std::string>();
                    return;
                }
            }
            if (parsed.contains("message") && parsed["message"].is_string())
            {
                result.summary = parsed["message"].get<std::string>();
                return;
            }
        }
        catch (...) {}

        if (response.statusCode != 0)
            result.summary = "VirusTotal returned HTTP " + std::to_string(response.statusCode);
        else
            result.summary = "VirusTotal request failed";
    }

    std::string ToUrlId(const std::string& value)
    {
        static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        int val = 0;
        int valb = -6;
        for (unsigned char c : value)
        {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0)
            {
                out.push_back(alphabet[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6)
            out.push_back(alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
        return out;
    }
}

bool EnsureRuntimeConfigReady()
{
    // seed the per-user runtime config from the packaged private config on first launch.
    const std::filesystem::path appDataConfigPath = bl::common::GetAppDataConfigPath();
    const std::filesystem::path bundledConfigPath = bl::common::GetBundledConfigPath();
    return CopyConfigIfMissing(bundledConfigPath, appDataConfigPath) || std::filesystem::exists(appDataConfigPath);
}

std::string LoadVTApiKey()
{
    // materialize the runtime config early so both installer and portable builds land on appdata.
    EnsureRuntimeConfigReady();

    const std::string envPrimary = ReadEnvVar("BINARYLENS_VT_API_KEY");
    if (!envPrimary.empty())
        return envPrimary;

    const std::string envFallback = ReadEnvVar("VT_API_KEY");
    if (!envFallback.empty())
        return envFallback;

    const std::vector<std::filesystem::path> localCandidates = {
        bl::common::GetAppDataConfigPath(),
        bl::common::GetBundledConfigPath()
    };

    for (const auto& candidate : localCandidates)
    {
        const std::string key = ReadKeyFromFile(candidate);
        if (!key.empty())
            return key;
    }

    return "";
}

ReputationResult QueryVirusTotalByHash(const std::string& sha256, const std::string& apiKey)
{
    ReputationResult result;

    if (sha256.empty())
    {
        result.summary = "SHA-256 hash unavailable";
        return result;
    }

    const std::string resolvedApiKey = apiKey.empty() ? LoadVTApiKey() : apiKey;
    if (resolvedApiKey.empty())
    {
        result.summary = "VirusTotal API key not configured";
        return result;
    }

    const HttpResponse response = PerformVirusTotalGet(L"/api/v3/files/" + Utf8ToWide(sha256), resolvedApiKey);
    FinalizeFromHttpResponse(response, result, "VirusTotal reputation data retrieved", "No record found for this SHA-256 hash");
    return result;
}

ReputationResult QueryVirusTotalUrl(const std::string& url, const std::string& apiKey)
{
    ReputationResult result;

    if (url.empty())
    {
        result.summary = "URL is empty";
        return result;
    }

    const std::string resolvedApiKey = apiKey.empty() ? LoadVTApiKey() : apiKey;
    if (resolvedApiKey.empty())
    {
        result.summary = "VirusTotal API key not configured";
        return result;
    }

    const HttpResponse response = PerformVirusTotalGet(L"/api/v3/urls/" + Utf8ToWide(ToUrlId(url)), resolvedApiKey);
    FinalizeFromHttpResponse(response, result, "VirusTotal URL reputation data retrieved", "No URL reputation record found in VirusTotal");
    return result;
}

ReputationResult QueryVirusTotalIp(const std::string& ip, const std::string& apiKey)
{
    ReputationResult result;

    if (ip.empty())
    {
        result.summary = "IP address is empty";
        return result;
    }

    const std::string resolvedApiKey = apiKey.empty() ? LoadVTApiKey() : apiKey;
    if (resolvedApiKey.empty())
    {
        result.summary = "VirusTotal API key not configured";
        return result;
    }

    const HttpResponse response = PerformVirusTotalGet(L"/api/v3/ip_addresses/" + Utf8ToWide(ip), resolvedApiKey);
    FinalizeFromHttpResponse(response, result, "VirusTotal IP reputation data retrieved", "No IP reputation record found in VirusTotal");
    return result;
}
