#include "services/api_client.h"
#include "third_party/json.hpp"

#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
// configuration and http helpers for virustotal lookups.

using json = nlohmann::json;

std::string LoadVTApiKey()
{
    // tries to read the api key from a json file and supports a small set of valid key names
    auto readKeyFromFile = [](const std::string& path) -> std::string
        {
            std::ifstream file(path);
            if (!file.is_open())
                return "";

            try
            {
                json config;
                file >> config;

                // keeps compatibility with both the current and legacy config field names
                if (config.contains("virustotal_api_key") && config["virustotal_api_key"].is_string())
                    return config["virustotal_api_key"].get<std::string>();

                if (config.contains("api_key") && config["api_key"].is_string())
                    return config["api_key"].get<std::string>();

                return "";
            }
            catch (...)
            {
                // returns empty on parse errors to avoid leaking internal loader/debug details into the ui
                return "";
            }
        };

    char exePath[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, exePath, MAX_PATH) == 0)
        return "";

    std::string fullPath = exePath;
    size_t lastSlash = fullPath.find_last_of("\\/");
    if (lastSlash == std::string::npos)
        return "";

    std::string exeDir = fullPath.substr(0, lastSlash + 1);

    const std::vector<std::string> candidates =
    {
        // visual studio classic layout: <repo>/x64/debug/binarylens.exe
        exeDir + "config.json",
        exeDir + "config/config.json",
        exeDir + "../../config.json",
        exeDir + "../../config/config.json",

        // qt/cmake layout: <repo>/out/build/x64-debug/binarylensqt.exe
        exeDir + "../../../BinaryLens/config/config.json",
        exeDir + "../../../../BinaryLens/config/config.json",

        // direct run from the repository root
        exeDir + "BinaryLens/config/config.json",
        exeDir + "config/config.json",

        // extra fallback for local variations that still keep a config folder near the root
        exeDir + "../../../config/config.json"
    };

    // stops at the first valid config file that yields a non-empty api key
    for (const auto& candidate : candidates)
    {
        std::string key = readKeyFromFile(candidate);
        if (!key.empty())
            return key;
    }

    return "";
}

namespace
{
    std::wstring Utf8ToWide(const std::string& input)
    {
        if (input.empty())
            return std::wstring();

        int size = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (size <= 0)
            return std::wstring();

        std::wstring output(size - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &output[0], size);
        return output;
    }

    std::string WideToUtf8(const std::wstring& input)
    {
        if (input.empty())
            return std::string();

        int size = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0)
            return std::string();

        std::string output(size - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &output[0], size, nullptr, nullptr);
        return output;
    }

    // these tiny extractors avoid pulling the full response into a richer model.
    std::string ExtractJsonIntField(const std::string& json, const std::string& key)
    {
        const std::string needle = "\"" + key + "\":";
        size_t pos = json.find(needle);
        if (pos == std::string::npos)
            return "";

        pos += needle.size();
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
            ++pos;

        size_t start = pos;
        while (pos < json.size() && (json[pos] == '-' || (json[pos] >= '0' && json[pos] <= '9')))
            ++pos;

        return json.substr(start, pos - start);
    }

    int ExtractJsonIntFieldValue(const std::string& json, const std::string& key)
    {
        std::string value = ExtractJsonIntField(json, key);
        if (value.empty())
            return 0;
        return std::atoi(value.c_str());
    }

    std::string ExtractJsonMessage(const std::string& json)
    {
        const std::string needle = "\"message\":\"";
        size_t pos = json.find(needle);
        if (pos == std::string::npos)
            return "";
        pos += needle.size();
        size_t end = json.find('"', pos);
        if (end == std::string::npos)
            return "";
        return json.substr(pos, end - pos);
    }
}

// this call only needs the file report summary, so it parses a small subset of the response.
ReputationResult QueryVirusTotalByHash(const std::string& sha256, const std::string& apiKey)
{
    ReputationResult result;

    if (sha256.empty())
    {
        result.summary = "SHA-256 hash unavailable";
        return result;
    }

    std::string resolvedApiKey = apiKey;

    if (resolvedApiKey.empty())
        resolvedApiKey = LoadVTApiKey();

    if (resolvedApiKey.empty())
    {
        result.summary = "VirusTotal API key not configured";
        return result;
    }

    HINTERNET hSession = WinHttpOpen(L"BinaryLens/0.6",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession)
    {
        result.summary = "Failed to open WinHTTP session";
        return result;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
    {
        result.summary = "Failed to connect to VirusTotal";
        WinHttpCloseHandle(hSession);
        return result;
    }

    // the file report endpoint is enough for the current reputation summary.
    std::wstring path = L"/api/v3/files/" + Utf8ToWide(sha256);
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!hRequest)
    {
        result.summary = "Failed to create VirusTotal request";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    std::wstring apiHeader = L"x-apikey: " + Utf8ToWide(resolvedApiKey);
    WinHttpAddRequestHeaders(hRequest, apiHeader.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    BOOL ok = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    if (ok)
        ok = WinHttpReceiveResponse(hRequest, nullptr);

    if (!ok)
    {
        result.summary = "VirusTotal request failed";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusCodeSize,
        WINHTTP_NO_HEADER_INDEX))
    {
        result.httpStatusCode = static_cast<int>(statusCode);
    }

    // accumulate the body manually because winhttp returns it in chunks.
    std::string response;
    DWORD availableSize = 0;
    do
    {
        availableSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &availableSize))
            break;

        if (availableSize == 0)
            break;

        std::vector<char> buffer(availableSize + 1, 0);
        DWORD bytesRead = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), availableSize, &bytesRead))
            break;

        response.append(buffer.data(), bytesRead);
    } while (availableSize > 0);

    result.rawResponse = response;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (result.httpStatusCode == 200)
    {
        result.maliciousDetections = ExtractJsonIntFieldValue(response, "malicious");
        result.suspiciousDetections = ExtractJsonIntFieldValue(response, "suspicious");
        result.harmlessDetections = ExtractJsonIntFieldValue(response, "harmless");
        result.undetectedDetections = ExtractJsonIntFieldValue(response, "undetected");
        result.success = true;
        result.summary = "VirusTotal reputation data retrieved";
        return result;
    }

    if (result.httpStatusCode == 404)
    {
        result.summary = "No record found for this SHA-256 hash";
        return result;
    }

    std::string message = ExtractJsonMessage(response);
    if (!message.empty())
        result.summary = message;
    else if (result.httpStatusCode != 0)
        result.summary = "VirusTotal returned HTTP " + std::to_string(result.httpStatusCode);
    else
        result.summary = "VirusTotal request failed";

    return result;
}


// queries the ip address endpoint so raw ip targets can carry reputation separate from url records.
ReputationResult QueryVirusTotalIp(const std::string& ip, const std::string& apiKey)
{
    ReputationResult result;

    if (ip.empty())
    {
        result.summary = "IP address is empty";
        return result;
    }

    std::string resolvedApiKey = apiKey.empty() ? LoadVTApiKey() : apiKey;
    if (resolvedApiKey.empty())
    {
        result.summary = "VirusTotal API key not configured";
        return result;
    }

    HINTERNET hSession = WinHttpOpen(L"BinaryLens/0.6", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
    {
        result.summary = "Failed to open WinHTTP session";
        return result;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
    {
        result.summary = "Failed to connect to VirusTotal";
        WinHttpCloseHandle(hSession);
        return result;
    }

    std::wstring path = L"/api/v3/ip_addresses/" + Utf8ToWide(ip);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest)
    {
        result.summary = "Failed to create VirusTotal request";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    std::wstring apiHeader = L"x-apikey: " + Utf8ToWide(resolvedApiKey);
    WinHttpAddRequestHeaders(hRequest, apiHeader.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok)
        ok = WinHttpReceiveResponse(hRequest, nullptr);

    if (!ok)
    {
        result.summary = "VirusTotal request failed";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX))
        result.httpStatusCode = static_cast<int>(statusCode);

    std::string response;
    DWORD availableSize = 0;
    do
    {
        availableSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &availableSize))
            break;
        if (availableSize == 0)
            break;

        std::vector<char> buffer(availableSize + 1, 0);
        DWORD bytesRead = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), availableSize, &bytesRead))
            break;

        response.append(buffer.data(), bytesRead);
    } while (availableSize > 0);

    result.rawResponse = response;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (result.httpStatusCode == 200)
    {
        result.maliciousDetections = ExtractJsonIntFieldValue(response, "malicious");
        result.suspiciousDetections = ExtractJsonIntFieldValue(response, "suspicious");
        result.harmlessDetections = ExtractJsonIntFieldValue(response, "harmless");
        result.undetectedDetections = ExtractJsonIntFieldValue(response, "undetected");
        result.success = true;
        result.summary = "VirusTotal IP reputation data retrieved";
        return result;
    }

    if (result.httpStatusCode == 404)
    {
        result.summary = "No IP reputation record found in VirusTotal";
        return result;
    }

    std::string message = ExtractJsonMessage(response);
    if (!message.empty())
        result.summary = message;
    else if (result.httpStatusCode != 0)
        result.summary = "VirusTotal returned HTTP " + std::to_string(result.httpStatusCode);
    else
        result.summary = "VirusTotal request failed";

    return result;
}
