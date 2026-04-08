#include "scanners/url_scanner.h"
#include "third_party/json.hpp"

#include <windows.h>
#include <winhttp.h>
#include <algorithm>
#include <cctype>
#include <string>
// network preflight scanner that normalizes urls and queries remote metadata safely.

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

// encoding, header parsing, and winhttp helpers shared by the remote scanner.
namespace
{
    constexpr int kResolveTimeoutMs = 6000;
    constexpr int kConnectTimeoutMs = 6000;
    constexpr int kSendTimeoutMs = 10000;
    constexpr int kReceiveTimeoutMs = 15000;
    constexpr std::size_t kMaxResponseBodyBytes = 1024u * 1024u;

    std::wstring ToWide(const std::string& input)
    // keeps string conversion in one place so the calling code does not repeat boundary work.
    {
        if (input.empty())
            return L"";

        const int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (sizeNeeded <= 0)
            return L"";

        // keep room for the terminator while the api writes into the temporary buffer.
        std::wstring result(static_cast<std::size_t>(sizeNeeded), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, result.data(), sizeNeeded);
        result.pop_back();
        return result;
    }

    std::string ToUtf8(const std::wstring& input)
    // keeps the to utf8 step local to this url scan flow file so callers can stay focused on intent.
    {
        if (input.empty())
            return {};
        const int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0)
            return {};
        std::string result(static_cast<std::size_t>(sizeNeeded), '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, result.data(), sizeNeeded, nullptr, nullptr);
        result.pop_back();
        return result;
    }

    std::string ToLowerCopy(const std::string& s)
    // normalizes text here so later comparisons stay simple and predictable.
    {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    int ReadNestedJsonInt(const json& object,
                          const std::initializer_list<const char*>& path,
                          int fallback = 0)
    // reads the read nested json int input here so bounds and fallback behavior stay local to this module.
    {
        const json* current = &object;
        for (const char* segment : path)
        {
            if (!segment || !current->is_object() || !current->contains(segment))
                return fallback;
            current = &(*current)[segment];
        }

        if (current->is_number_integer() || current->is_number_unsigned())
            return current->get<int>();
        if (current->is_string())
        {
            try
            {
                return std::stoi(current->get<std::string>());
            }
            catch (const std::exception&)
            {
            }
            return fallback;
        }

        return fallback;
    }

    // urlhaus lookups need compact encodings for some request paths.
    std::string Base64Encode(const std::string& input)
    // keeps the base64 encode step local to this url scan flow file so callers can stay focused on intent.
    {
        static const char table[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        std::string output;
        int val = 0;
        int valb = -6;

        for (unsigned char c : input)
        {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0)
            {
                output.push_back(table[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }

        if (valb > -6)
            output.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);

        while (output.size() % 4)
            output.push_back('=');

        return output;
    }

    std::string Base64UrlEncodeNoPadding(const std::string& input)
    // keeps the base64 url encode no padding step local to this url scan flow file so callers can stay focused on intent.
    {
        std::string b64 = Base64Encode(input);

        for (char& c : b64)
        {
            if (c == '+')
                c = '-';
            else if (c == '/')
                c = '_';
        }

        while (!b64.empty() && b64.back() == '=')
            b64.pop_back();

        return b64;
    }

    std::wstring QueryHeaderWideString(HINTERNET hRequest, DWORD query)
    // keeps the query header wide string step local to this url scan flow file so callers can stay focused on intent.
    {
        DWORD size = 0;
        if (WinHttpQueryHeaders(hRequest, query, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX))
            return {};
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size < sizeof(wchar_t))
            return {};

        std::wstring buffer(size / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryHeaders(hRequest, query, WINHTTP_HEADER_NAME_BY_INDEX, buffer.data(), &size, WINHTTP_NO_HEADER_INDEX))
            return {};
        if (!buffer.empty() && buffer.back() == L'\0')
            buffer.pop_back();
        return buffer;
    }

    // header access is centralized so each query keeps the same buffer-growth logic.
    std::string QueryHeaderString(HINTERNET hRequest, DWORD query)
    // keeps the query header string step local to this url scan flow file so callers can stay focused on intent.
    {
        return ToUtf8(QueryHeaderWideString(hRequest, query));
    }


    bool ApplyWinHttpHardening(HINTERNET hSession, HINTERNET hRequest)
    // keeps the apply win http hardening step local to this url scan flow file so callers can stay focused on intent.
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
        }

        return true;
    }

    // content-disposition can expose a staged payload name even before a download happens.
    std::string GuessFileNameFromDisposition(const std::string& header)
    // keeps the guess file name from disposition step local to this url scan flow file so callers can stay focused on intent.
    {
        const std::string lower = ToLowerCopy(header);
        const std::string token = "filename=";
        const std::size_t pos = lower.find(token);
        if (pos == std::string::npos)
            return {};

        std::string value = header.substr(pos + token.size());
        if (!value.empty() && (value.front() == '"' || value.front() == '\''))
            value.erase(value.begin());
        while (!value.empty() && (value.back() == '"' || value.back() == '\'' || value.back() == ';' || std::isspace(static_cast<unsigned char>(value.back()))))
            value.pop_back();
        return value;
    }
}

// quick gate used to distinguish probable urls from generic text input.
bool LooksLikeURL(const std::string& input)
// answers this looks like url check in one place so the surrounding logic stays readable.
{
    if (input.empty())
        return false;

    std::string lower = ToLowerCopy(input);

    if (lower.rfind("http://", 0) == 0 || lower.rfind("https://", 0) == 0)
        return true;

    if (lower.find('.') != std::string::npos && lower.find(' ') == std::string::npos)
        return true;

    return false;
}

// normalizes user input into a fetchable url while preserving the intended host and path.
// normalize missing schemes up front so downstream network calls stay predictable.
std::string NormalizeURL(const std::string& input)
// keeps the normalize url step local to this url scan flow file so callers can stay focused on intent.
{
    if (input.empty())
        return input;

    std::string trimmed = input;

    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.front())))
        trimmed.erase(trimmed.begin());

    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.back())))
        trimmed.pop_back();

    const std::string lower = ToLowerCopy(trimmed);
    if (lower.rfind("http://", 0) == 0 || lower.rfind("https://", 0) == 0)
        return trimmed;

    return "https://" + trimmed;
}

URLReputationResult QueryVirusTotalURL(const std::string& url, const std::string& apiKey)
// keeps the query virus total url step local to this url scan flow file so callers can stay focused on intent.
{
    URLReputationResult result;

    if (url.empty())
    {
        result.summary = "URL is empty";
        return result;
    }

    if (apiKey.empty())
    {
        result.summary = "VirusTotal API key not configured";
        return result;
    }

    const std::string urlId = Base64UrlEncodeNoPadding(url);
    const std::wstring host = L"www.virustotal.com";
    const std::wstring path = ToWide("/api/v3/urls/" + urlId);

    HINTERNET hSession = WinHttpOpen(L"BinaryLens/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS,
                                     0);
    if (!hSession)
    {
        result.summary = "Failed to initialize WinHTTP";
        return result;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
    {
        result.summary = "Failed to connect to VirusTotal";
        WinHttpCloseHandle(hSession);
        return result;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
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

    if (!ApplyWinHttpHardening(hSession, hRequest))
    {
        result.summary = "Failed to harden VirusTotal request";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    const std::wstring headers = ToWide("x-apikey: " + apiKey + "\r\naccept: application/json\r\n");
    BOOL sent = WinHttpSendRequest(hRequest,
                                   headers.c_str(),
                                   static_cast<DWORD>(headers.size()),
                                   WINHTTP_NO_REQUEST_DATA,
                                   0,
                                   0,
                                   0);

    if (!sent)
    {
        result.summary = "Failed to send VirusTotal request";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    BOOL received = WinHttpReceiveResponse(hRequest, nullptr);
    if (!received)
    {
        result.summary = "Failed to receive VirusTotal response";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &statusCode,
                        &statusCodeSize,
                        WINHTTP_NO_HEADER_INDEX);

    result.httpStatusCode = static_cast<int>(statusCode);

    std::string responseBody;
    while (true)
    {
        DWORD availableSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &availableSize))
            break;
        if (availableSize == 0)
            break;

        if (responseBody.size() >= kMaxResponseBodyBytes)
            break;

        const std::size_t chunkBudget = kMaxResponseBodyBytes - responseBody.size();
        const DWORD chunkSize = static_cast<DWORD>(std::min<std::size_t>(chunkBudget, static_cast<std::size_t>(availableSize)));
        if (chunkSize == 0)
            break;

        std::string chunk(chunkSize, '\0');
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, chunk.data(), chunkSize, &downloaded))
            break;

        if (downloaded == 0)
            break;

        responseBody.append(chunk.data(), downloaded);
    }

    result.rawResponse = responseBody;

    if (statusCode == 200)
    {
        try
        {
            const json parsed = json::parse(responseBody);
            result.success = true;
            result.maliciousDetections = ReadNestedJsonInt(parsed, {"data", "attributes", "last_analysis_stats", "malicious"});
            result.suspiciousDetections = ReadNestedJsonInt(parsed, {"data", "attributes", "last_analysis_stats", "suspicious"});
            result.harmlessDetections = ReadNestedJsonInt(parsed, {"data", "attributes", "last_analysis_stats", "harmless"});
            result.undetectedDetections = ReadNestedJsonInt(parsed, {"data", "attributes", "last_analysis_stats", "undetected"});
            result.summary = "Reputation data retrieved";
        }
        catch (const std::exception&)
        {
            result.summary = "VirusTotal returned unreadable JSON";
        }
    }
    else if (statusCode == 404)
    {
        result.summary = "URL not found in VirusTotal";
    }
    else if (statusCode == 401 || statusCode == 403)
    {
        result.summary = "VirusTotal authentication failed";
    }
    else
    {
        result.summary = "VirusTotal request failed with HTTP " + std::to_string(statusCode);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

// this preflight only fetches headers and a tiny prefix, not the full body.
URLPreflightResult FetchURLPreflight(const std::string& url)
// reads the fetch urlpreflight input here so bounds and fallback behavior stay local to this module.
{
    URLPreflightResult result;
    if (url.empty())
    {
        result.summary = "URL is empty";
        return result;
    }

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t hostBuffer[512]{};
    wchar_t pathBuffer[4096]{};
    wchar_t extraBuffer[4096]{};
    uc.lpszHostName = hostBuffer;
    uc.dwHostNameLength = static_cast<DWORD>(std::size(hostBuffer));
    uc.lpszUrlPath = pathBuffer;
    uc.dwUrlPathLength = static_cast<DWORD>(std::size(pathBuffer));
    uc.lpszExtraInfo = extraBuffer;
    uc.dwExtraInfoLength = static_cast<DWORD>(std::size(extraBuffer));

    const std::wstring wideUrl = ToWide(url);
    if (wideUrl.empty() || !WinHttpCrackUrl(wideUrl.c_str(), 0, 0, &uc))
    {
        result.summary = "Failed to parse URL";
        return result;
    }

    const bool https = uc.nScheme == INTERNET_SCHEME_HTTPS;
    const INTERNET_PORT port = uc.nPort ? uc.nPort : static_cast<INTERNET_PORT>(https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT);
    std::wstring path = std::wstring(uc.lpszUrlPath, uc.dwUrlPathLength) + std::wstring(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    if (path.empty())
        path = L"/";

    HINTERNET hSession = WinHttpOpen(L"BinaryLens/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS,
                                     0);
    if (!hSession)
    {
        result.summary = "Failed to initialize WinHTTP";
        return result;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, std::wstring(uc.lpszHostName, uc.dwHostNameLength).c_str(), port, 0);
    if (!hConnect)
    {
        result.summary = "Failed to connect to host";
        WinHttpCloseHandle(hSession);
        return result;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
                                            L"HEAD",
                                            path.c_str(),
                                            nullptr,
                                            WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            https ? WINHTTP_FLAG_SECURE : 0);

    if (!hRequest)
    {
        result.summary = "Failed to create preflight request";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    if (!ApplyWinHttpHardening(hSession, hRequest))
    {
        result.summary = "Failed to harden preflight request";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok)
        ok = WinHttpReceiveResponse(hRequest, nullptr);

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (ok)
    {
        WinHttpQueryHeaders(hRequest,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &statusCode,
                            &statusSize,
                            WINHTTP_NO_HEADER_INDEX);
        result.httpStatusCode = static_cast<int>(statusCode);
        result.success = true;
    }

    result.contentType = QueryHeaderString(hRequest, WINHTTP_QUERY_CONTENT_TYPE);
    result.contentDisposition = QueryHeaderString(hRequest, WINHTTP_QUERY_CONTENT_DISPOSITION);
    result.serverHeader = QueryHeaderString(hRequest, WINHTTP_QUERY_SERVER);
    result.suggestedFileName = GuessFileNameFromDisposition(result.contentDisposition);

    const std::wstring redirectLocation = QueryHeaderWideString(hRequest, WINHTTP_QUERY_LOCATION);
    if (!redirectLocation.empty())
    {
        result.followedRedirect = true;
        result.finalUrl = ToUtf8(redirectLocation);
    }

    const std::wstring contentLength = QueryHeaderWideString(hRequest, WINHTTP_QUERY_CONTENT_LENGTH);
    if (!contentLength.empty())
    {
        try
        {
            result.contentLength = static_cast<std::uint64_t>(std::stoull(ToUtf8(contentLength)));
        }
        catch (const std::exception&) {}
    }

    const std::string lowerType = ToLowerCopy(result.contentType);
    result.likelyHtml = lowerType.find("text/html") != std::string::npos || lowerType.find("application/xhtml") != std::string::npos;
    result.likelyExecutable = lowerType.find("application/x-msdownload") != std::string::npos ||
                              lowerType.find("application/octet-stream") != std::string::npos && !result.suggestedFileName.empty();
    result.likelyArchive = lowerType.find("zip") != std::string::npos || lowerType.find("rar") != std::string::npos ||
                           lowerType.find("7z") != std::string::npos || lowerType.find("cab") != std::string::npos;
    result.likelyScript = lowerType.find("javascript") != std::string::npos || lowerType.find("powershell") != std::string::npos ||
                          lowerType.find("vbscript") != std::string::npos || lowerType.find("text/plain") != std::string::npos && !result.suggestedFileName.empty();
    result.likelyDownload = result.likelyExecutable || result.likelyArchive || result.likelyScript ||
                            ToLowerCopy(result.contentDisposition).find("attachment") != std::string::npos;

    if (result.success)
        result.summary = "Preflight metadata retrieved";
    else
        result.summary = "Preflight request failed";

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}
