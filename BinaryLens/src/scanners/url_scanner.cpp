#include "scanners/url_scanner.h"

#include <windows.h>
#include <winhttp.h>
#include <algorithm>
#include <cctype>
#include <string>
// network preflight scanner that normalizes urls and queries remote metadata safely.

#pragma comment(lib, "winhttp.lib")

// encoding, header parsing, and winhttp helpers shared by the remote scanner.
namespace
{
    std::wstring ToWide(const std::string& input)
    {
        if (input.empty())
            return L"";

        int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (sizeNeeded <= 0)
            return L"";

        std::wstring result(static_cast<std::size_t>(sizeNeeded - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, result.data(), sizeNeeded);
        return result;
    }

    std::string ToUtf8(const std::wstring& input)
    {
        if (input.empty())
            return {};
        const int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0)
            return {};
        std::string result(static_cast<std::size_t>(sizeNeeded - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, result.data(), sizeNeeded, nullptr, nullptr);
        return result;
    }

    std::string ToLowerCopy(const std::string& s)
    {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    std::string ExtractJSONIntField(const std::string& json, const std::string& fieldName)
    {
        const std::string key = "\"" + fieldName + "\"";
        size_t pos = json.find(key);
        if (pos == std::string::npos)
            return "";

        pos = json.find(':', pos);
        if (pos == std::string::npos)
            return "";

        ++pos;
        while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])))
            ++pos;

        size_t end = pos;
        while (end < json.size() && (std::isdigit(static_cast<unsigned char>(json[end])) || json[end] == '-'))
            ++end;

        if (end <= pos)
            return "";

        return json.substr(pos, end - pos);
    }

    int ParseIntOrDefault(const std::string& s, int fallback = 0)
    {
        if (s.empty())
            return fallback;

        try
        {
            return std::stoi(s);
        }
        catch (...)
        {
            return fallback;
        }
    }

    std::string Base64Encode(const std::string& input)
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

    std::string QueryHeaderString(HINTERNET hRequest, DWORD query)
    {
        wchar_t buffer[4096]{};
        DWORD size = sizeof(buffer);
        if (!WinHttpQueryHeaders(hRequest, query, WINHTTP_HEADER_NAME_BY_INDEX, buffer, &size, WINHTTP_NO_HEADER_INDEX))
            return {};
        return ToUtf8(buffer);
    }

    std::string GuessFileNameFromDisposition(const std::string& header)
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
std::string NormalizeURL(const std::string& input)
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

        std::string chunk(availableSize, '\0');
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, chunk.data(), availableSize, &downloaded))
            break;

        if (downloaded == 0)
            break;

        responseBody.append(chunk.data(), downloaded);
    }

    result.rawResponse = responseBody;

    if (statusCode == 200)
    {
        result.success = true;
        result.maliciousDetections = ParseIntOrDefault(ExtractJSONIntField(responseBody, "malicious"));
        result.suspiciousDetections = ParseIntOrDefault(ExtractJSONIntField(responseBody, "suspicious"));
        result.harmlessDetections = ParseIntOrDefault(ExtractJSONIntField(responseBody, "harmless"));
        result.undetectedDetections = ParseIntOrDefault(ExtractJSONIntField(responseBody, "undetected"));
        result.summary = "Reputation data retrieved";
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

URLPreflightResult FetchURLPreflight(const std::string& url)
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

    wchar_t locationBuffer[4096]{};
    DWORD locationSize = sizeof(locationBuffer);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX, locationBuffer, &locationSize, WINHTTP_NO_HEADER_INDEX))
    {
        result.followedRedirect = true;
        result.finalUrl = ToUtf8(locationBuffer);
    }

    wchar_t lengthBuffer[128]{};
    DWORD lengthSize = sizeof(lengthBuffer);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lengthBuffer, &lengthSize, WINHTTP_NO_HEADER_INDEX))
    {
        try
        {
            result.contentLength = static_cast<std::uint64_t>(std::stoull(ToUtf8(lengthBuffer)));
        }
        catch (...) {}
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
