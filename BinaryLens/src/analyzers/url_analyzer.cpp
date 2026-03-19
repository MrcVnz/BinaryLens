#include "analyzers/url_analyzer.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>
// url decomposition, redirect handling, and suspicious pattern scoring.

#define _CRT_SECURE_NO_WARNINGS

// url parsing helpers, normalization routines, and redirect-aware path utilities.
namespace
{
    std::string ToLower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return value;
    }

    void AddUnique(std::vector<std::string>& items, const std::string& value)
    {
        if (value.empty())
            return;
        if (std::find(items.begin(), items.end(), value) == items.end())
            items.push_back(value);
    }

    void AddSignal(UrlAnalysis& out, const std::string& signal)
    {
        AddUnique(out.securitySignals, signal);
    }

    std::wstring Utf8ToWide(const std::string& input)
    {
        if (input.empty())
            return std::wstring();
        const int size = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (size <= 0)
            return std::wstring();
        std::wstring output(static_cast<std::size_t>(size - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, output.data(), size);
        return output;
    }

    std::string WideToUtf8(const std::wstring& input)
    {
        if (input.empty())
            return std::string();
        const int size = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0)
            return std::string();
        std::string output(static_cast<std::size_t>(size - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, output.data(), size, nullptr, nullptr);
        return output;
    }

    bool IsHex(char c)
    {
        return std::isxdigit(static_cast<unsigned char>(c)) != 0;
    }

    int HexValue(char c)
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        return 0;
    }

    std::string PercentDecodeOnce(const std::string& input)
    {
        std::string output;
        output.reserve(input.size());

        for (std::size_t i = 0; i < input.size(); ++i)
        {
            if (input[i] == '%' && i + 2 < input.size() && IsHex(input[i + 1]) && IsHex(input[i + 2]))
            {
                const char decoded = static_cast<char>((HexValue(input[i + 1]) << 4) | HexValue(input[i + 2]));
                output.push_back(decoded);
                i += 2;
            }
            else if (input[i] == '+')
            {
                output.push_back(' ');
            }
            else
            {
                output.push_back(input[i]);
            }
        }
        return output;
    }

    std::string PercentDecodeRecursive(const std::string& input, bool& doubleEncoded)
    {
        doubleEncoded = false;
        std::string current = input;
        for (int i = 0; i < 3; ++i)
        {
            const std::string decoded = PercentDecodeOnce(current);
            if (decoded == current)
                break;
            if (i >= 1)
                doubleEncoded = true;
            current = decoded;
        }
        return current;
    }

    bool IsIpAddress(const std::string& host)
    {
        sockaddr_in sa4{};
        sockaddr_in6 sa6{};
        return inet_pton(AF_INET, host.c_str(), &(sa4.sin_addr)) == 1 ||
               inet_pton(AF_INET6, host.c_str(), &(sa6.sin6_addr)) == 1;
    }

    bool CrackUrlParts(const std::string& url, UrlAnalysis& out)
    {
        URL_COMPONENTS uc{};
        uc.dwStructSize = sizeof(uc);
        wchar_t hostBuffer[512]{};
        wchar_t pathBuffer[4096]{};
        wchar_t extraBuffer[4096]{};
        wchar_t schemeBuffer[32]{};
        uc.lpszHostName = hostBuffer;
        uc.dwHostNameLength = static_cast<DWORD>(std::size(hostBuffer));
        uc.lpszUrlPath = pathBuffer;
        uc.dwUrlPathLength = static_cast<DWORD>(std::size(pathBuffer));
        uc.lpszExtraInfo = extraBuffer;
        uc.dwExtraInfoLength = static_cast<DWORD>(std::size(extraBuffer));
        uc.lpszScheme = schemeBuffer;
        uc.dwSchemeLength = static_cast<DWORD>(std::size(schemeBuffer));

        const std::wstring wideUrl = Utf8ToWide(url);
        if (wideUrl.empty() || !WinHttpCrackUrl(wideUrl.c_str(), 0, 0, &uc))
            return false;

        out.scheme = WideToUtf8(std::wstring(uc.lpszScheme, uc.dwSchemeLength));
        out.host = WideToUtf8(std::wstring(uc.lpszHostName, uc.dwHostNameLength));
        out.path = WideToUtf8(std::wstring(uc.lpszUrlPath, uc.dwUrlPathLength));
        out.query = WideToUtf8(std::wstring(uc.lpszExtraInfo, uc.dwExtraInfoLength));
        out.https = uc.nScheme == INTERNET_SCHEME_HTTPS;
        out.hasQuery = !out.query.empty();
        if (uc.nPort != INTERNET_DEFAULT_HTTP_PORT && uc.nPort != INTERNET_DEFAULT_HTTPS_PORT)
            out.port = std::to_string(uc.nPort);
        else
            out.port.clear();

        const std::size_t hashPos = url.find('#');
        out.fragment = (hashPos == std::string::npos) ? std::string() : url.substr(hashPos + 1);
        return true;
    }

    std::vector<std::string> Split(const std::string& value, char delim, bool skipEmpty = true)
    {
        std::vector<std::string> parts;
        std::string current;
        for (char c : value)
        {
            if (c == delim)
            {
                if (!current.empty() || !skipEmpty)
                    parts.push_back(current);
                current.clear();
            }
            else
            {
                current.push_back(c);
            }
        }
        if (!current.empty() || !skipEmpty)
            parts.push_back(current);
        return parts;
    }

    std::string ExtractRegisteredDomain(const std::string& host)
    {
        if (host.empty() || IsIpAddress(host))
            return host;
        const std::vector<std::string> parts = Split(host, '.');
        if (parts.size() <= 2)
            return host;
        return parts[parts.size() - 2] + "." + parts[parts.size() - 1];
    }

    std::string ExtractSubdomain(const std::string& host, const std::string& domain)
    {
        if (host.empty() || domain.empty() || host == domain)
            return "";
        if (host.size() <= domain.size() + 1)
            return "";
        return host.substr(0, host.size() - domain.size() - 1);
    }

    std::string ResolveIp(const std::string& host, std::string& ipVersion)
    {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* result = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0)
            return "";

        char ipStr[INET6_ADDRSTRLEN]{};
        std::string output;
        for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next)
        {
            if (ptr->ai_family == AF_INET)
            {
                const sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
                inet_ntop(AF_INET, &(addr->sin_addr), ipStr, sizeof(ipStr));
                ipVersion = "IPv4";
                output = ipStr;
                break;
            }
            if (ptr->ai_family == AF_INET6)
            {
                const sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(ptr->ai_addr);
                inet_ntop(AF_INET6, &(addr->sin6_addr), ipStr, sizeof(ipStr));
                ipVersion = "IPv6";
                output = ipStr;
                break;
            }
        }
        freeaddrinfo(result);
        return output;
    }

    std::string ReverseLookup(const std::string& ip)
    {
        char host[NI_MAXHOST]{};
        sockaddr_storage storage{};
        socklen_t size = 0;
        if (ip.find(':') != std::string::npos)
        {
            sockaddr_in6* sa6 = reinterpret_cast<sockaddr_in6*>(&storage);
            sa6->sin6_family = AF_INET6;
            inet_pton(AF_INET6, ip.c_str(), &sa6->sin6_addr);
            size = sizeof(sockaddr_in6);
        }
        else
        {
            sockaddr_in* sa4 = reinterpret_cast<sockaddr_in*>(&storage);
            sa4->sin_family = AF_INET;
            inet_pton(AF_INET, ip.c_str(), &sa4->sin_addr);
            size = sizeof(sockaddr_in);
        }
        if (getnameinfo(reinterpret_cast<sockaddr*>(&storage), size, host, sizeof(host), nullptr, 0, 0) == 0)
            return host;
        return "";
    }

    bool StartsWith(const std::string& value, const std::string& prefix)
    {
        return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
    }

    std::string BuildAbsoluteUrl(const std::string& baseUrl, const std::string& location)
    {
        if (location.empty())
            return "";
        if (StartsWith(location, "http://") || StartsWith(location, "https://"))
            return location;

        UrlAnalysis tmp;
        if (!CrackUrlParts(baseUrl, tmp))
            return location;

        const std::string scheme = tmp.scheme.empty() ? "https" : tmp.scheme;
        if (!location.empty() && location[0] == '/')
            return scheme + "://" + tmp.host + location;
        return scheme + "://" + tmp.host + "/" + location;
    }

    std::string ResolveRedirectChain(const std::string& url, int& redirectCount, bool& redirected)
    {
        redirectCount = 0;
        redirected = false;
        std::string currentUrl = url;
        HINTERNET hSession = WinHttpOpen(L"BinaryLens/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
            return currentUrl;

        for (int i = 0; i < 5; ++i)
        {
            UrlAnalysis parts;
            if (!CrackUrlParts(currentUrl, parts))
                break;

            INTERNET_PORT port = parts.port.empty()
                ? static_cast<INTERNET_PORT>(parts.https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT)
                : static_cast<INTERNET_PORT>(std::stoi(parts.port));

            HINTERNET hConnect = WinHttpConnect(hSession, Utf8ToWide(parts.host).c_str(), port, 0);
            if (!hConnect)
                break;

            std::wstring path = Utf8ToWide(parts.path + parts.query);
            if (path.empty())
                path = L"/";

            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HEAD", path.c_str(), nullptr,
                                                    WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                    parts.https ? WINHTTP_FLAG_SECURE : 0);
            if (!hRequest)
            {
                WinHttpCloseHandle(hConnect);
                break;
            }

            DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

            BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
            if (ok)
                ok = WinHttpReceiveResponse(hRequest, nullptr);

            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

            if (statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308)
            {
                wchar_t locationBuffer[4096]{};
                DWORD locationSize = sizeof(locationBuffer);
                if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                                        locationBuffer, &locationSize, WINHTTP_NO_HEADER_INDEX))
                {
                    const std::string nextUrl = BuildAbsoluteUrl(currentUrl, WideToUtf8(locationBuffer));
                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    if (nextUrl.empty() || nextUrl == currentUrl)
                        break;
                    currentUrl = nextUrl;
                    redirected = true;
                    ++redirectCount;
                    continue;
                }
            }

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            break;
        }

        WinHttpCloseHandle(hSession);
        return currentUrl;
    }

    std::string ExtractJsonString(const std::string& json, const std::string& key)
    {
        const std::string token = "\"" + key + "\":";
        const std::size_t pos = json.find(token);
        if (pos == std::string::npos)
            return "";
        std::size_t start = json.find('"', pos + token.size());
        if (start == std::string::npos)
            return "";
        ++start;
        std::size_t end = json.find('"', start);
        if (end == std::string::npos)
            return "";
        return json.substr(start, end - start);
    }

    bool ExtractJsonBool(const std::string& json, const std::string& key, bool defaultValue = false)
    {
        const std::string token = "\"" + key + "\":";
        const std::size_t pos = json.find(token);
        if (pos == std::string::npos)
            return defaultValue;
        const std::size_t valuePos = pos + token.size();
        if (json.compare(valuePos, 4, "true") == 0)
            return true;
        if (json.compare(valuePos, 5, "false") == 0)
            return false;
        return defaultValue;
    }

    void ClassifyIpAddress(UrlAnalysis& result)
    {
        if (result.resolvedIp.empty() || result.ipVersion != "IPv4")
            return;

        unsigned int a = 0, b = 0, c = 0, d = 0;
        if (sscanf_s(result.resolvedIp.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
            return;

        if (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || a == 127)
        {
            result.isPrivateIp = true;
            AddSignal(result, "Private or local IP range detected");
            return;
        }

        if (a == 0 || a >= 224 || (a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127))
        {
            result.isReservedIp = true;
            AddSignal(result, "Reserved, link-local, multicast, or carrier-grade NAT range detected");
        }
    }

    void QueryIpMetadata(UrlAnalysis& result)
    {
        if (result.resolvedIp.empty())
            return;

        const std::wstring host = L"ip-api.com";
        const std::wstring path = Utf8ToWide("/json/" + result.resolvedIp + "?fields=status,country,regionName,city,isp,org,as,hosting,proxy,mobile,query");

        HINTERNET hSession = WinHttpOpen(L"BinaryLens/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
            return;

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return;
        }

        std::string body;
        BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (ok)
            ok = WinHttpReceiveResponse(hRequest, nullptr);

        while (ok)
        {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &available) || available == 0)
                break;
            std::string buffer(available, '\0');
            DWORD downloaded = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), available, &downloaded) || downloaded == 0)
                break;
            body.append(buffer.data(), downloaded);
        }

        if (!body.empty() && body.find("\"status\":\"success\"") != std::string::npos)
        {
            result.providerLookupSucceeded = true;
            result.provider = ExtractJsonString(body, "isp");
            result.organization = ExtractJsonString(body, "org");
            result.asn = ExtractJsonString(body, "as");
            result.country = ExtractJsonString(body, "country");
            result.region = ExtractJsonString(body, "regionName");
            result.city = ExtractJsonString(body, "city");
            const bool hosting = ExtractJsonBool(body, "hosting");
            const bool proxy = ExtractJsonBool(body, "proxy");
            result.likelySharedHosting = hosting;
            result.likelyExclusiveIp = !hosting && !proxy;
            if (hosting)
                result.hostingType = "Likely shared hosting or cloud infrastructure";
            else if (proxy)
                result.hostingType = "Likely proxy, relay, or masked infrastructure";
            else
                result.hostingType = "Likely dedicated or exclusive IP";
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
    }

    bool HostEndsWith(const std::string& host, const std::string& suffix)
    {
        if (host.size() < suffix.size())
            return false;
        return host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    void ClassifyProviderSignals(UrlAnalysis& result)
    {
        const std::string joined = ToLower(result.provider + " " + result.organization + " " + result.asn + " " + result.reverseDns);
        if (joined.find("cloudflare") != std::string::npos || joined.find("akamai") != std::string::npos ||
            joined.find("fastly") != std::string::npos || joined.find("amazon") != std::string::npos ||
            joined.find("azure") != std::string::npos || joined.find("google cloud") != std::string::npos)
        {
            result.cloudOrCdnInfrastructure = true;
            AddSignal(result, "Cloud, CDN, or large shared edge infrastructure detected");
            AddUnique(result.domainContextTags, "cloud_or_cdn");
        }

        if (joined.find("cloudflare") != std::string::npos || joined.find("microsoft") != std::string::npos ||
            joined.find("google") != std::string::npos || joined.find("amazon") != std::string::npos ||
            joined.find("akamai") != std::string::npos)
        {
            result.knownSafeProvider = true;
            AddUnique(result.domainContextTags, "known_safe_provider");
        }

        if (joined.find("duckdns") != std::string::npos || joined.find("no-ip") != std::string::npos ||
            joined.find("dyn") != std::string::npos)
        {
            result.likelyDynamicDns = true;
            AddSignal(result, "Dynamic DNS or frequently changing host infrastructure detected");
            AddUnique(result.domainContextTags, "dynamic_dns");
        }
    }

    int CountOccurrences(const std::string& haystack, const std::string& needle)
    {
        if (needle.empty())
            return 0;
        int count = 0;
        std::size_t pos = 0;
        while ((pos = haystack.find(needle, pos)) != std::string::npos)
        {
            ++count;
            pos += needle.size();
        }
        return count;
    }

    std::string StripLeadingSlash(const std::string& value)
    {
        if (!value.empty() && value.front() == '/')
            return value.substr(1);
        return value;
    }

    std::string GuessPayloadType(const std::string& fileName)
    {
        const std::string lower = ToLower(fileName);
        static const std::array<const char*, 9> executables = { ".exe", ".dll", ".msi", ".scr", ".iso", ".img", ".hta", ".lnk", ".jar" };
        for (const char* ext : executables)
        {
            if (HostEndsWith(lower, ext))
                return "Executable or launcher-style payload";
        }
        static const std::array<const char*, 6> archives = { ".zip", ".rar", ".7z", ".cab", ".tar", ".gz" };
        for (const char* ext : archives)
        {
            if (HostEndsWith(lower, ext))
                return "Archive delivery";
        }
        static const std::array<const char*, 8> scripts = { ".ps1", ".bat", ".cmd", ".js", ".vbs", ".wsf", ".hta", ".psm1" };
        for (const char* ext : scripts)
        {
            if (HostEndsWith(lower, ext))
                return "Script delivery";
        }
        return "";
    }

    void EvaluateUrlStructure(const std::string& analysisTarget, UrlAnalysis& result)
    {
        result.normalizedHost = ToLower(result.host);
        result.normalizedPath = PercentDecodeOnce(result.path);
        result.decodedUrl = PercentDecodeRecursive(analysisTarget, result.doubleEncoded);
        if (result.doubleEncoded)
        {
            AddSignal(result, "Double-encoded URL components detected");
            AddUnique(result.domainContextTags, "double_encoded");
        }

        const std::string lowerUrl = ToLower(analysisTarget);
        const std::string lowerHost = result.normalizedHost;
        const std::string lowerDecoded = ToLower(result.decodedUrl);

        result.hostLabelCount = static_cast<int>(Split(result.host, '.').size());
        result.hasExcessiveSubdomains = result.hostLabelCount >= 5;
        if (result.hasExcessiveSubdomains)
        {
            AddSignal(result, "Excessive subdomain depth detected");
            AddUnique(result.domainContextTags, "deep_subdomain");
        }

        result.longHostName = result.host.size() >= 45;
        if (result.longHostName)
            AddSignal(result, "Long host name detected");

        result.punycode = lowerHost.find("xn--") != std::string::npos;
        if (result.punycode)
        {
            AddSignal(result, "Punycode detected in host");
            AddUnique(result.domainContextTags, "punycode");
        }

        static const std::array<const char*, 8> suspiciousTlds = { ".ru", ".cn", ".tk", ".top", ".xyz", ".gq", ".click", ".work" };
        for (const char* tld : suspiciousTlds)
        {
            if (HostEndsWith(lowerHost, tld))
            {
                result.suspiciousTld = true;
                AddSignal(result, "Suspicious top-level domain detected");
                AddUnique(result.domainContextTags, "suspicious_tld");
                break;
            }
        }

        static const std::array<const char*, 16> shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "adf.ly", "bit.do",
            "cutt.ly", "ow.ly", "shorturl.at", "rebrand.ly", "shorte.st", "bl.ink", "lnkd.in", "rb.gy"
        };
        for (const char* shortener : shorteners)
        {
            if (lowerHost == shortener || HostEndsWith(lowerHost, std::string(".") + shortener))
            {
                result.usesShortener = true;
                AddSignal(result, "URL shortener service detected");
                AddUnique(result.domainContextTags, "shortener");
                break;
            }
        }

        if (!result.port.empty())
        {
            result.nonStandardPort = true;
            result.suspiciousPort = result.port != "443" && result.port != "80" && result.port != "8080" && result.port != "8443";
            if (result.suspiciousPort)
                AddSignal(result, "Non-standard or uncommon service port detected");
        }

        const std::size_t schemePos = lowerUrl.find("://");
        if (schemePos != std::string::npos)
        {
            const std::size_t authorityStart = schemePos + 3;
            const std::size_t authorityEnd = lowerUrl.find_first_of("/?#", authorityStart);
            const std::string authority = lowerUrl.substr(authorityStart, authorityEnd == std::string::npos ? std::string::npos : authorityEnd - authorityStart);
            result.hasAtSymbol = authority.find('@') != std::string::npos;
            result.hasUserInfo = result.hasAtSymbol;
            if (result.hasAtSymbol)
            {
                AddSignal(result, "User-info or '@' redirect-style URL trick detected");
                AddUnique(result.domainContextTags, "userinfo");
            }
        }

        result.suspiciousQuery = lowerDecoded.find("cmd=") != std::string::npos ||
                                 lowerDecoded.find("exec=") != std::string::npos ||
                                 lowerDecoded.find("base64") != std::string::npos ||
                                 lowerDecoded.find("powershell") != std::string::npos ||
                                 lowerDecoded.find("token=") != std::string::npos ||
                                 lowerDecoded.find("auth=") != std::string::npos ||
                                 lowerDecoded.find("session=") != std::string::npos ||
                                 lowerDecoded.find("redirect=") != std::string::npos ||
                                 lowerDecoded.find("return=") != std::string::npos ||
                                 lowerDecoded.find("url=") != std::string::npos;
        if (result.suspiciousQuery)
            AddSignal(result, "Suspicious query parameters or execution-oriented strings detected");

        result.suspiciousEncodedSegments = lowerUrl.find("%2f") != std::string::npos || lowerUrl.find("%3a") != std::string::npos ||
                                          lowerUrl.find("%5c") != std::string::npos || lowerDecoded.find("://") != std::string::npos && lowerUrl.find("%") != std::string::npos;
        if (result.suspiciousEncodedSegments)
            AddSignal(result, "Encoded or obfuscated URL segments detected");

        result.queryParameterCount = 0;
        result.longestQueryValueLength = 0;
        std::string cleanQuery = result.query;
        if (!cleanQuery.empty() && cleanQuery.front() == '?')
            cleanQuery.erase(cleanQuery.begin());
        if (!cleanQuery.empty())
        {
            const auto params = Split(cleanQuery, '&');
            result.queryParameterCount = static_cast<int>(params.size());
            for (const auto& param : params)
            {
                const std::size_t eq = param.find('=');
                const std::string value = (eq == std::string::npos) ? std::string() : param.substr(eq + 1);
                if (static_cast<int>(value.size()) > result.longestQueryValueLength)
                    result.longestQueryValueLength = static_cast<int>(value.size());
            }
            result.longQueryBlob = result.longestQueryValueLength >= 80 || cleanQuery.size() >= 180;
            if (result.longQueryBlob)
                AddSignal(result, "Large encoded or campaign-style query blob detected");
        }

        result.pathSegmentCount = 0;
        const auto pathSegments = Split(StripLeadingSlash(result.path), '/');
        for (const auto& segment : pathSegments)
        {
            if (!segment.empty())
                ++result.pathSegmentCount;
        }
        if (result.pathSegmentCount >= 6)
            AddSignal(result, "Deep path hierarchy detected");

        result.suspiciousPath = lowerDecoded.find("/login") != std::string::npos || lowerDecoded.find("/signin") != std::string::npos ||
                                lowerDecoded.find("/verify") != std::string::npos || lowerDecoded.find("/update") != std::string::npos ||
                                lowerDecoded.find("/secure") != std::string::npos || lowerDecoded.find("/account") != std::string::npos ||
                                lowerDecoded.find("/invoice") != std::string::npos || lowerDecoded.find("/download") != std::string::npos;
        if (result.suspiciousPath)
            AddSignal(result, "Credential, delivery, or account-themed path pattern detected");

        const std::array<const char*, 12> suspiciousKeywords = {
            "invoice", "payment", "wallet", "gift", "crypto", "airdrop",
            "login", "verify", "secure", "download", "update", "document"
        };
        for (const char* token : suspiciousKeywords)
            result.suspiciousKeywordHits += CountOccurrences(lowerDecoded, token);
        result.suspiciousKeywords = result.suspiciousKeywordHits >= 2;
        if (result.suspiciousKeywords)
            AddSignal(result, "Multiple lure or phishing-oriented keywords detected");

        result.likelyFileName.clear();
        if (!pathSegments.empty())
        {
            const std::string tail = pathSegments.back();
            if (tail.find('.') != std::string::npos)
                result.likelyFileName = tail;
        }
        result.likelyPayloadType = GuessPayloadType(result.likelyFileName);
        result.likelyExecutableDownload = result.likelyPayloadType.find("Executable") != std::string::npos;
        result.likelyArchiveDownload = result.likelyPayloadType.find("Archive") != std::string::npos;
        result.likelyScriptDownload = result.likelyPayloadType.find("Script") != std::string::npos;
        result.suspiciousFileExtension = result.likelyExecutableDownload || result.likelyArchiveDownload || result.likelyScriptDownload;
        result.directFileLink = result.suspiciousFileExtension && !result.likelyFileName.empty();
        if (result.directFileLink)
            AddSignal(result, "Direct file-delivery style URL detected");

        static const std::array<const char*, 10> safeDomains = {
            "microsoft.com", "aka.ms", "google.com", "gstatic.com", "github.com",
            "githubusercontent.com", "cloudflare.com", "amazonaws.com", "office.com", "live.com"
        };
        for (const char* safe : safeDomains)
        {
            if (lowerHost == safe || HostEndsWith(lowerHost, std::string(".") + safe))
            {
                result.knownSafeDomain = true;
                result.domainTrustLabel = "Known trusted domain family";
                AddUnique(result.domainContextTags, "trusted_domain");
                break;
            }
        }
        if (result.domainTrustLabel.empty())
            result.domainTrustLabel = result.knownSafeProvider ? "Known provider infrastructure" : "Unclassified domain";

        static const std::array<const char*, 6> dynamicDns = { "duckdns.org", "ddns.net", "no-ip.org", "hopto.org", "servehttp.com", "zapto.org" };
        for (const char* dyn : dynamicDns)
        {
            if (lowerHost == dyn || HostEndsWith(lowerHost, std::string(".") + dyn))
            {
                result.likelyDynamicDns = true;
                AddSignal(result, "Dynamic DNS provider domain detected");
                break;
            }
        }

        static const std::array<const char*, 8> brands = { "microsoft", "google", "apple", "steam", "paypal", "discord", "telegram", "binance" };
        for (const char* brand : brands)
        {
            const std::string b = brand;
            const bool referenced = lowerDecoded.find(b) != std::string::npos;
            const bool inHost = lowerHost.find(b) != std::string::npos || result.domain == (b + ".com");
            if (referenced && !inHost)
            {
                result.likelyBrandImpersonation = true;
                result.impersonatedBrand = b;
                AddSignal(result, "Possible brand impersonation or lure mismatch detected");
                AddUnique(result.domainContextTags, "brand_impersonation");
                break;
            }
        }

        result.loginBrandLure = (lowerDecoded.find("login") != std::string::npos || lowerDecoded.find("signin") != std::string::npos) &&
                                result.likelyBrandImpersonation;
        result.likelyCredentialHarvest = result.loginBrandLure || (result.suspiciousPath && result.likelyBrandImpersonation);
        result.likelyPayloadDelivery = result.usesShortener || result.directFileLink || result.likelyScriptDownload || result.likelyArchiveDownload || result.likelyExecutableDownload;

        if (result.likelyCredentialHarvest)
            result.urlCategory = "Likely credential collection";
        else if (result.likelyPayloadDelivery)
            result.urlCategory = "Likely payload delivery";
        else if (result.redirected && result.usesShortener)
            result.urlCategory = "Likely redirect chain";
        else if (result.knownSafeDomain || result.knownSafeProvider)
            result.urlCategory = "Likely benign infrastructure";
        else
            result.urlCategory = "Unclassified web target";

        if (result.likelyPayloadDelivery)
            AddUnique(result.behaviorHints, "Would likely deliver or stage a downloadable payload");
        if (result.redirected && result.redirectCount > 0)
            AddUnique(result.behaviorHints, "Would likely redirect the browser before final content is reached");
        if (result.likelyCredentialHarvest)
            AddUnique(result.behaviorHints, "Would likely present a credential collection or account-verification flow");
        if (result.usesShortener)
            AddUnique(result.behaviorHints, "Would likely obscure final destination until resolution time");
        if (result.suspiciousQuery || result.longQueryBlob)
            AddUnique(result.behaviorHints, "Would likely pass campaign, session, or execution-oriented tokens in the query string");
    }
}

UrlAnalysis AnalyzeUrl(const std::string& url)
{
    UrlAnalysis result;
    result.originalUrl = url;
    result.normalizedUrl = url;

    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return result;

    CrackUrlParts(url, result);
    result.finalUrl = ResolveRedirectChain(url, result.redirectCount, result.redirected);
    const std::string analysisTarget = (result.redirected && !result.finalUrl.empty()) ? result.finalUrl : url;
    result.effectiveHost.clear();
    CrackUrlParts(analysisTarget, result);
    result.effectiveHost = result.host;

    result.domain = ExtractRegisteredDomain(result.host);
    result.subdomain = ExtractSubdomain(result.host, result.domain);
    result.isIp = IsIpAddress(result.host);
    result.rawIpUrl = result.isIp;
    if (result.isIp)
        AddSignal(result, "URL uses a direct IP address instead of a domain");

    EvaluateUrlStructure(analysisTarget, result);

    if (result.isIp)
    {
        result.resolvedIp = result.host;
        result.ipVersion = result.host.find(':') != std::string::npos ? "IPv6" : "IPv4";
    }
    else
    {
        result.resolvedIp = ResolveIp(result.host, result.ipVersion);
    }

    if (!result.resolvedIp.empty())
        result.reverseDns = ReverseLookup(result.resolvedIp);

    ClassifyIpAddress(result);
    QueryIpMetadata(result);
    ClassifyProviderSignals(result);

    if (result.redirected)
        AddSignal(result, "URL performs redirect chaining before final destination");
    if (!result.https)
        AddSignal(result, "URL does not use HTTPS");
    if (result.rawIpUrl && !result.likelyExclusiveIp)
        AddSignal(result, "Direct IP plus shared infrastructure can indicate disposable hosting");
    if (result.knownSafeDomain)
        AddSignal(result, "Known trusted domain family detected");
    if (result.directFileLink && result.likelyExecutableDownload)
        AddSignal(result, "URL likely points directly to an executable or launcher-style file");
    if (result.directFileLink && result.likelyScriptDownload)
        AddSignal(result, "URL likely points directly to a script-capable file");
    if (result.directFileLink && result.likelyArchiveDownload)
        AddSignal(result, "URL likely points directly to an archive or staged delivery package");

    if (result.redirected && !result.finalUrl.empty())
        result.normalizedIndicators.push_back("Final URL: " + result.finalUrl);
    if (!result.likelyFileName.empty())
        result.normalizedIndicators.push_back("Likely File: " + result.likelyFileName);
    if (!result.likelyPayloadType.empty())
        result.normalizedIndicators.push_back("Likely Payload Type: " + result.likelyPayloadType);
    if (!result.domainTrustLabel.empty())
        result.normalizedIndicators.push_back("Domain Trust: " + result.domainTrustLabel);

    WSACleanup();
    return result;
}
