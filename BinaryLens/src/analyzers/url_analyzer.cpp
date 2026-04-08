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
#include "third_party/json.hpp"
// url decomposition, redirect handling, and suspicious pattern scoring.

using json = nlohmann::json;

#define _CRT_SECURE_NO_WARNINGS

// url parsing helpers, normalization routines, and redirect-aware path utilities.
namespace
{
    std::string ToLower(std::string value)
    // normalizes text here so later comparisons stay simple and predictable.
    {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return value;
    }

    // keeps network probes short enough that raw ip lookups do not stall the ui.
    void SetWinHttpShortTimeouts(HINTERNET handle)
    // keeps the set win http short timeouts step local to this url analysis file so callers can stay focused on intent.
    {
        if (!handle)
            return;

        const int resolveTimeoutMs = 2500;
        const int connectTimeoutMs = 2500;
        const int sendTimeoutMs = 3000;
        const int receiveTimeoutMs = 3000;
        WinHttpSetTimeouts(handle, resolveTimeoutMs, connectTimeoutMs, sendTimeoutMs, receiveTimeoutMs);
    }

    void AddUnique(std::vector<std::string>& items, const std::string& value)
    // adds this detail through one gate so duplicate or noisy output stays under control.
    {
        if (value.empty())
            return;
        if (std::find(items.begin(), items.end(), value) == items.end())
            items.push_back(value);
    }

    void AddSignal(UrlAnalysis& out, const std::string& signal)
    // adds this detail through one gate so duplicate or noisy output stays under control.
    {
        AddUnique(out.securitySignals, signal);
    }

    std::wstring Utf8ToWide(const std::string& input)
    // keeps the utf8 to wide step local to this url analysis file so callers can stay focused on intent.
    {
        if (input.empty())
            return std::wstring();
        const int size = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (size <= 0)
            return std::wstring();
        // keep room for the terminator while the win32 api writes the converted buffer.
        std::wstring output(static_cast<std::size_t>(size), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, output.data(), size);
        output.pop_back();
        return output;
    }

    std::string WideToUtf8(const std::wstring& input)
    // keeps the wide to utf8 step local to this url analysis file so callers can stay focused on intent.
    {
        if (input.empty())
            return std::string();
        const int size = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0)
            return std::string();
        std::string output(static_cast<std::size_t>(size), '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, output.data(), size, nullptr, nullptr);
        output.pop_back();
        return output;
    }

    std::wstring QueryHeaderWideString(HINTERNET request, DWORD query)
    // keeps the query header wide string step local to this url analysis file so callers can stay focused on intent.
    {
        DWORD size = 0;
        if (WinHttpQueryHeaders(request, query, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX))
            return {};
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size < sizeof(wchar_t))
            return {};

        std::wstring buffer(size / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryHeaders(request, query, WINHTTP_HEADER_NAME_BY_INDEX, buffer.data(), &size, WINHTTP_NO_HEADER_INDEX))
            return {};
        if (!buffer.empty() && buffer.back() == L'\0')
            buffer.pop_back();
        return buffer;
    }

    bool IsHex(char c)
    // answers this is hex check in one place so the surrounding logic stays readable.
    {
        return std::isxdigit(static_cast<unsigned char>(c)) != 0;
    }

    int HexValue(char c)
    // keeps the hex value step local to this url analysis file so callers can stay focused on intent.
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        return 0;
    }

    std::string PercentDecodeOnce(const std::string& input)
    // keeps the percent decode once step local to this url analysis file so callers can stay focused on intent.
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

    // decode a few rounds so nested campaign encoding still shows up in later checks.
    std::string PercentDecodeRecursive(const std::string& input, bool& doubleEncoded)
    // keeps the percent decode recursive step local to this url analysis file so callers can stay focused on intent.
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
    // answers this is ip address check in one place so the surrounding logic stays readable.
    {
        sockaddr_in sa4{};
        sockaddr_in6 sa6{};
        return inet_pton(AF_INET, host.c_str(), &(sa4.sin_addr)) == 1 ||
               inet_pton(AF_INET6, host.c_str(), &(sa6.sin6_addr)) == 1;
    }

    // rely on winhttp parsing so host, path, and port stay consistent with windows behavior.
    bool CrackUrlParts(const std::string& url, UrlAnalysis& out)
    // keeps the crack url parts step local to this url analysis file so callers can stay focused on intent.
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
    // keeps the split step local to this url analysis file so callers can stay focused on intent.
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
    // collects the extract registered domain data for this url analysis step before higher level code consumes it.
    {
        if (host.empty() || IsIpAddress(host))
            return host;
        const std::vector<std::string> parts = Split(host, '.');
        if (parts.size() <= 2)
            return host;
        return parts[parts.size() - 2] + "." + parts[parts.size() - 1];
    }

    std::string ExtractSubdomain(const std::string& host, const std::string& domain)
    // collects the extract subdomain data for this url analysis step before higher level code consumes it.
    {
        if (host.empty() || domain.empty() || host == domain)
            return "";
        if (host.size() <= domain.size() + 1)
            return "";
        return host.substr(0, host.size() - domain.size() - 1);
    }

    // prefer the first successful dns answer because this pass classifies, not inventories dns.
    std::string ResolveIp(const std::string& host, std::string& ipVersion)
    // maps raw resolve ip data into something the rest of the url analysis path can reason about.
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
    // keeps the reverse lookup step local to this url analysis file so callers can stay focused on intent.
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
        {
            const std::string value = host;
            if (ToLower(value) == ToLower(ip))
                return "";
            return value;
        }
        return "";
    }

    std::string ExtractAsNumber(const std::string& asField)
    // collects the extract as number data for this url analysis step before higher level code consumes it.
    {
        if (asField.empty())
            return "";

        const std::size_t first = asField.find("AS");
        if (first == std::string::npos)
            return "";

        std::size_t end = first + 2;
        while (end < asField.size() && std::isdigit(static_cast<unsigned char>(asField[end])))
            ++end;

        return asField.substr(first, end - first);
    }

    std::string ExtractAsName(const std::string& asField)
    // collects the extract as name data for this url analysis step before higher level code consumes it.
    {
        if (asField.empty())
            return "";

        const std::size_t pos = asField.find(' ');
        if (pos == std::string::npos || pos + 1 >= asField.size())
            return "";

        return asField.substr(pos + 1);
    }

    bool ContainsAny(const std::string& haystack, const std::initializer_list<const char*>& needles)
    // answers this contains any check in one place so the surrounding logic stays readable.
    {
        for (const char* needle : needles)
        {
            if (haystack.find(needle) != std::string::npos)
                return true;
        }
        return false;
    }

    std::string BuildOwnershipSummary(const UrlAnalysis& result)
    // builds this url analysis fragment in one place so the surrounding code can stay focused on flow.
    {
        std::vector<std::string> parts;
        if (!result.organization.empty())
            parts.push_back(result.organization);
        else if (!result.provider.empty())
            parts.push_back(result.provider);

        if (!result.asn.empty() && !result.asName.empty())
            parts.push_back(result.asn + " " + result.asName);
        else if (!result.asn.empty())
            parts.push_back(result.asn);
        else if (!result.asName.empty())
            parts.push_back(result.asName);

        if (!result.country.empty())
            parts.push_back(result.country);

        if (parts.empty())
            return "";

        std::string summary = parts.front();
        for (std::size_t i = 1; i < parts.size(); ++i)
            summary += " | " + parts[i];
        return summary;
    }

    std::string InferInfrastructureClass(const UrlAnalysis& result)
    // keeps the infer infrastructure class step local to this url analysis file so callers can stay focused on intent.
    {
        const std::string joined = ToLower(result.host + " " + result.reverseDns + " " + result.provider + " " + result.organization + " " + result.asn + " " + result.asName);

        if (result.isPrivateIp || result.isLoopbackIp || result.localNetworkHost)
            return "Internal, lab, or local-network target";
        if (ContainsAny(joined, {"riot", "pvp.net", "leagueoflegends", "valorant", "battle.net", "steam", "valve", "epic"}))
            return "Game platform or gameplay infrastructure";
        if (ContainsAny(joined, {"cloudflare", "akamai", "fastly", "cloudfront", "edge", "cdn", "cache", "gstatic", "fbcdn"}))
            return "CDN, edge, or reverse-proxy infrastructure";
        if (ContainsAny(joined, {"aws", "amazon", "azure", "google cloud", "gcp", "digitalocean", "linode", "ovh", "hetzner", "vultr"}))
            return "Cloud, VPS, or hosted workload infrastructure";
        if (ContainsAny(joined, {"comcast", "telefonica", "claro", "vivo", "oi", "tim brasil", "residential", "broadband", "cable", "dsl", "fiber"}))
            return "Consumer broadband or residential access network";
        if (!result.organization.empty() || !result.provider.empty())
            return "Organization-owned or provider-operated infrastructure";
        return "Unclassified network infrastructure";
    }

    std::string InferExposureLabel(const UrlAnalysis& result)
    // keeps the infer exposure label step local to this url analysis file so callers can stay focused on intent.
    {
        if (result.isPrivateIp || result.isLoopbackIp || result.localNetworkHost)
            return "Internal or local-scope target";
        if (result.isDocumentationIp)
            return "Documentation or test-only target";
        if (result.isReservedIp)
            return "Special-use or reserved-scope target";
        return "Public internet-reachable target";
    }

    std::string InferServicePurpose(const UrlAnalysis& result)
    // keeps the infer service purpose step local to this url analysis file so callers can stay focused on intent.
    {
        const std::string joined = ToLower(result.host + " " + result.reverseDns + " " + result.provider + " " + result.organization + " " + result.asn + " " + result.asName);

        if (ContainsAny(joined, {"riot", "pvp.net", "leagueoflegends", "valorant"}))
            return "Likely game backend, session, or anti-cheat-adjacent service infrastructure";
        if (ContainsAny(joined, {"steam", "valve", "steampowered"}))
            return "Likely game platform, patch, matchmaking, or content service infrastructure";
        if (ContainsAny(joined, {"discord"}))
            return "Likely messaging, media relay, or api-edge service infrastructure";
        if (ContainsAny(joined, {"meta", "facebook", "fbcdn", "whatsapp", "instagram"}))
            return "Likely large-platform edge, messaging, or application delivery infrastructure";
        if (ContainsAny(joined, {"google", "youtube", "gstatic"}))
            return "Likely api-edge, platform, or cached static-content infrastructure";
        if (ContainsAny(joined, {"microsoft", "azure", "outlook", "office", "bing"}))
            return "Likely corporate service, cloud workload, or platform edge infrastructure";
        if (ContainsAny(joined, {"amazon", "aws", "cloudfront"}))
            return "Likely cloud workload, object delivery, or edge-served application infrastructure";
        if (ContainsAny(joined, {"cloudflare", "akamai", "fastly"}))
            return "Likely api edge, content delivery, or reverse-proxy infrastructure";
        if (ContainsAny(joined, {"digitalocean", "linode", "ovh", "hetzner", "vultr"}))
            return "Likely hosting, vps node, or general-purpose cloud workload infrastructure";
        if (ContainsAny(joined, {"cdn", "edge", "cache", "static", "shv"}))
            return "Likely cache, edge-delivery, or static-content serving infrastructure";
        if (ContainsAny(joined, {"broadband", "fiber", "dsl", "cable"}))
            return "Likely consumer broadband or last-mile access network";
        if (result.rawIpUrl && !result.organization.empty())
            return "Likely service owned or operated by the identified organization";
        if (result.rawIpUrl && !result.provider.empty())
            return "Likely service operating on the identified provider network";
        return "";
    }

    bool StartsWith(const std::string& value, const std::string& prefix)
    // keeps the starts with step local to this url analysis file so callers can stay focused on intent.
    {
        return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
    }

    // rebuild relative redirects against the last seen absolute url.
    std::string BuildAbsoluteUrl(const std::string& baseUrl, const std::string& location)
    // builds this url analysis fragment in one place so the surrounding code can stay focused on flow.
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

    // follow a short redirect chain so scoring targets the final destination when possible.
    std::string ResolveRedirectChain(const std::string& url, int& redirectCount, bool& redirected)
    // maps raw resolve redirect chain data into something the rest of the url analysis path can reason about.
    {
        redirectCount = 0;
        redirected = false;
        std::string currentUrl = url;
        HINTERNET hSession = WinHttpOpen(L"BinaryLens/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
            return currentUrl;

        SetWinHttpShortTimeouts(hSession);

        for (int i = 0; i < 5; ++i)
        {
            UrlAnalysis parts;
            if (!CrackUrlParts(currentUrl, parts))
                break;

            INTERNET_PORT port = static_cast<INTERNET_PORT>(parts.https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT);
            if (!parts.port.empty())
            {
                try
                {
                    port = static_cast<INTERNET_PORT>(std::stoi(parts.port));
                }
                catch (const std::exception&)
                {
                    break;
                }
            }

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
                const std::wstring redirectLocation = QueryHeaderWideString(hRequest, WINHTTP_QUERY_LOCATION);
                if (!redirectLocation.empty())
                {
                    const std::string nextUrl = BuildAbsoluteUrl(currentUrl, WideToUtf8(redirectLocation));
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
    // collects the extract json string data for this url analysis step before higher level code consumes it.
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
    // collects the extract json bool data for this url analysis step before higher level code consumes it.
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

    // separate private, reserved, and likely shared-hosting cases before provider tagging.
    void ClassifyIpAddress(UrlAnalysis& result)
    // classifies the classify ip address result here so later stages can work with stable labels.
    {
        if (result.resolvedIp.empty() || result.ipVersion != "IPv4")
            return;

        unsigned int a = 0, b = 0, c = 0, d = 0;
        if (sscanf_s(result.resolvedIp.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
            return;

        if (a == 127)
        {
            result.isPrivateIp = true;
            result.isLoopbackIp = true;
            AddSignal(result, "Loopback IP range detected");
            return;
        }

        if (a == 169 && b == 254)
        {
            result.isReservedIp = true;
            result.isLinkLocalIp = true;
            AddSignal(result, "Link-local IP range detected");
            return;
        }

        if (a == 100 && b >= 64 && b <= 127)
        {
            result.isReservedIp = true;
            result.isCarrierGradeNatIp = true;
            AddSignal(result, "Carrier-grade NAT range detected");
            return;
        }

        if ((a == 192 && b == 0 && c == 2) ||
            (a == 198 && b == 51 && c == 100) ||
            (a == 203 && b == 0 && c == 113))
        {
            result.isReservedIp = true;
            result.isDocumentationIp = true;
            AddSignal(result, "Documentation or example IP range detected");
            return;
        }

        if (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168))
        {
            result.isPrivateIp = true;
            AddSignal(result, "Private IP range detected");
            return;
        }

        if (a == 0 || a >= 224)
        {
            result.isReservedIp = true;
            AddSignal(result, "Reserved, multicast, or special-use IP range detected");
        }
    }

    // uses a small reusable winhttp get path so multiple enrichment providers can be queried consistently.
    std::string DownloadHttpBody(const std::wstring& host, INTERNET_PORT port, const std::wstring& path, bool secure)
    // keeps the download http body step local to this url analysis file so callers can stay focused on intent.
    {
        HINTERNET hSession = WinHttpOpen(L"BinaryLens/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
            return "";

        SetWinHttpShortTimeouts(hSession);

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return "";
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"GET",
            path.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            secure ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
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

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return body;
    }

    // keeps the strongest metadata already seen and fills only the gaps left by a weaker provider.
    void FillIfEmpty(std::string& target, const std::string& value)
    // keeps the fill if empty step local to this url analysis file so callers can stay focused on intent.
    {
        if (target.empty() && !value.empty())
            target = value;
    }

    // applies ip-api fields when that provider responds successfully.
    bool ApplyIpApiMetadata(const std::string& body, UrlAnalysis& result)
    // keeps the apply ip api metadata step local to this url analysis file so callers can stay focused on intent.
    {
        if (body.empty() || body.find("\"status\":\"success\"") == std::string::npos)
            return false;

        result.providerLookupSucceeded = true;
        FillIfEmpty(result.provider, ExtractJsonString(body, "isp"));
        FillIfEmpty(result.organization, ExtractJsonString(body, "org"));

        const std::string asField = ExtractJsonString(body, "as");
        FillIfEmpty(result.asn, ExtractAsNumber(asField));
        FillIfEmpty(result.asName, ExtractJsonString(body, "asname"));
        if (result.asName.empty())
            FillIfEmpty(result.asName, ExtractAsName(asField));

        FillIfEmpty(result.country, ExtractJsonString(body, "country"));
        FillIfEmpty(result.region, ExtractJsonString(body, "regionName"));
        FillIfEmpty(result.city, ExtractJsonString(body, "city"));

        const bool hosting = ExtractJsonBool(body, "hosting");
        const bool proxy = ExtractJsonBool(body, "proxy");
        const std::string reverseField = ExtractJsonString(body, "reverse");
        if (result.reverseDns.empty() && !reverseField.empty() && ToLower(reverseField) != ToLower(result.resolvedIp))
            result.reverseDns = reverseField;

        if (hosting)
        {
            result.likelySharedHosting = true;
            result.likelyExclusiveIp = false;
            FillIfEmpty(result.hostingType, "Likely shared hosting or cloud infrastructure");
        }
        else if (proxy)
        {
            result.likelyExclusiveIp = false;
            FillIfEmpty(result.hostingType, "Likely proxy, relay, or masked infrastructure");
        }
        else if (!result.organization.empty() || !result.provider.empty())
        {
            result.likelyExclusiveIp = true;
            FillIfEmpty(result.hostingType, "Likely dedicated or exclusive IP");
        }

        return true;
    }

    // uses an https fallback so raw ip enrichment still succeeds when the first provider is unavailable.
    bool ApplyIpWhoIsMetadata(const std::string& body, UrlAnalysis& result)
    // keeps the apply ip who is metadata step local to this url analysis file so callers can stay focused on intent.
    {
        if (body.empty())
            return false;

        try
        {
            const json parsed = json::parse(body);
            if (parsed.contains("success") && !parsed.value("success", false))
                return false;

            result.providerLookupSucceeded = true;

            if (parsed.contains("connection") && parsed["connection"].is_object())
            {
                const auto& connection = parsed["connection"];
                if (result.provider.empty() && connection.contains("isp") && connection["isp"].is_string())
                    result.provider = connection["isp"].get<std::string>();
                if (result.organization.empty() && connection.contains("org") && connection["org"].is_string())
                    result.organization = connection["org"].get<std::string>();
                if (result.asn.empty() && connection.contains("asn"))
                {
                    if (connection["asn"].is_string())
                        result.asn = connection["asn"].get<std::string>();
                    else if (connection["asn"].is_number_integer())
                        result.asn = "AS" + std::to_string(connection["asn"].get<int>());
                }
                if (result.asn.rfind("AS", 0) != 0 && !result.asn.empty())
                    result.asn = "AS" + result.asn;
                if (result.asName.empty() && connection.contains("domain") && connection["domain"].is_string())
                    result.asName = connection["domain"].get<std::string>();
                if (connection.contains("type") && connection["type"].is_string())
                {
                    const std::string type = ToLower(connection["type"].get<std::string>());
                    if (type.find("hosting") != std::string::npos)
                    {
                        result.likelySharedHosting = true;
                        result.likelyExclusiveIp = false;
                        FillIfEmpty(result.hostingType, "Likely shared hosting or cloud infrastructure");
                    }
                    else if (type.find("isp") != std::string::npos || type.find("business") != std::string::npos)
                    {
                        if (!result.likelySharedHosting)
                            result.likelyExclusiveIp = true;
                        FillIfEmpty(result.hostingType, "Likely provider-operated or organization-owned infrastructure");
                    }
                }
            }

            if (result.country.empty() && parsed.contains("country") && parsed["country"].is_string())
                result.country = parsed["country"].get<std::string>();
            if (result.region.empty() && parsed.contains("region") && parsed["region"].is_string())
                result.region = parsed["region"].get<std::string>();
            if (result.city.empty() && parsed.contains("city") && parsed["city"].is_string())
                result.city = parsed["city"].get<std::string>();
        }
        catch (...)
        {
            return false;
        }

        return true;
    }

    // ip metadata now uses https-only enrichment providers to avoid insecure lookups in a security tool.
    void QueryIpMetadata(UrlAnalysis& result)
    // keeps the query ip metadata step local to this url analysis file so callers can stay focused on intent.
    {
        if (result.resolvedIp.empty())
            return;

        const std::string ipWhoIsBody = DownloadHttpBody(
            L"ipwho.is",
            INTERNET_DEFAULT_HTTPS_PORT,
            Utf8ToWide("/" + result.resolvedIp),
            true);
        ApplyIpWhoIsMetadata(ipWhoIsBody, result);

        if (result.reverseDns.empty())
            result.reverseDns = ReverseLookup(result.resolvedIp);

        if (!result.likelySharedHosting && !result.likelyExclusiveIp && (!result.organization.empty() || !result.provider.empty()))
            result.likelyExclusiveIp = true;
    }

    bool HostEndsWith(const std::string& host, const std::string& suffix)
    // keeps the host ends with step local to this url analysis file so callers can stay focused on intent.
    {
        if (host.size() < suffix.size())
            return false;
        return host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    bool IsLocalHostName(const std::string& host)
    // answers this is local host name check in one place so the surrounding logic stays readable.
    {
        const std::string lower = ToLower(host);
        return lower == "localhost" || lower == "localhost.localdomain" ||
               HostEndsWith(lower, ".local") || HostEndsWith(lower, ".lan") || HostEndsWith(lower, ".home");
    }

    // provider labels are context only, not a clean-safe verdict.
    void ClassifyProviderSignals(UrlAnalysis& result)
    // classifies the classify provider signals result here so later stages can work with stable labels.
    {
        const std::string joined = ToLower(result.provider + " " + result.organization + " " + result.asn + " " + result.reverseDns);
        if (joined.find("cloudflare") != std::string::npos || joined.find("akamai") != std::string::npos ||
            joined.find("fastly") != std::string::npos || joined.find("amazon") != std::string::npos ||
            joined.find("azure") != std::string::npos || joined.find("google cloud") != std::string::npos ||
            joined.find("fbcdn") != std::string::npos || joined.find("meta") != std::string::npos ||
            joined.find("cloudfront") != std::string::npos || joined.find("gstatic") != std::string::npos)
        {
            result.cloudOrCdnInfrastructure = true;
            AddSignal(result, "Cloud, CDN, or large shared edge infrastructure detected");
            AddUnique(result.domainContextTags, "shared_edge_infrastructure");
        }

        if (joined.find("cloudflare") != std::string::npos || joined.find("microsoft") != std::string::npos ||
            joined.find("google") != std::string::npos || joined.find("amazon") != std::string::npos ||
            joined.find("akamai") != std::string::npos || joined.find("meta") != std::string::npos ||
            joined.find("facebook") != std::string::npos || joined.find("riot") != std::string::npos ||
            joined.find("valve") != std::string::npos || joined.find("steam") != std::string::npos)
        {
            result.knownSafeProvider = true;
            AddUnique(result.domainContextTags, "established_provider_context");
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
    // keeps the count occurrences step local to this url analysis file so callers can stay focused on intent.
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
    // keeps the strip leading slash step local to this url analysis file so callers can stay focused on intent.
    {
        if (!value.empty() && value.front() == '/')
            return value.substr(1);
        return value;
    }

    std::string GuessPayloadType(const std::string& fileName)
    // keeps the guess payload type step local to this url analysis file so callers can stay focused on intent.
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

    // score only on shape and content here; network metadata is added later.
    void EvaluateUrlStructure(const std::string& analysisTarget, UrlAnalysis& result)
    // keeps the evaluate url structure step local to this url analysis file so callers can stay focused on intent.
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

        // file-sharing and paste platforms are not malicious by themselves, but they matter when delivery traits also stack up.
        static const std::array<const char*, 10> fileShareProviders = {
            "dropbox.com", "drive.google.com", "docs.google.com", "onedrive.live.com", "1drv.ms",
            "mega.nz", "mediafire.com", "discord.com", "discord.gg", "pastebin.com"
        };
        for (const char* provider : fileShareProviders)
        {
            if (lowerHost == provider || HostEndsWith(lowerHost, std::string(".") + provider))
            {
                result.knownFileShareProvider = true;
                AddSignal(result, "Known file-sharing or paste-style provider detected");
                AddUnique(result.domainContextTags, "file_share_provider");
                break;
            }
        }

        result.localNetworkHost = IsLocalHostName(lowerHost);
        if (result.localNetworkHost)
        {
            AddSignal(result, "Local-host or private-lab style hostname detected");
            AddUnique(result.domainContextTags, "internal_or_local_target");
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

        // mixed encoding plus traversal markers often shows up in redirectors and obfuscated paths.
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

        // known platforms get a trust tag, but that does not suppress every other signal.
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
        if (result.rawIpUrl)
            result.domainTrustLabel = result.knownSafeProvider ? "Direct IP on identified provider network" : "Direct IP target";
        else if (result.domainTrustLabel.empty())
            result.domainTrustLabel = result.knownSafeProvider ? "Known provider infrastructure" : "Unclassified domain";

        // dynamic dns is worth surfacing because throwaway campaigns lean on it often.
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

        // flag brand mentions in the path or query when the host itself does not match.
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
        else if (result.rawIpUrl)
            result.urlCategory = "Direct IP service endpoint";
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
        if (result.knownFileShareProvider && result.directFileLink)
            AddUnique(result.behaviorHints, "Would likely stage a payload through a mainstream file-sharing or paste-style platform");
        if (result.localNetworkHost || result.isPrivateIp || result.isLoopbackIp)
            AddUnique(result.behaviorHints, "Would likely target an internal, lab, or local-network service rather than a public internet host");
        if (result.suspiciousQuery || result.longQueryBlob)
            AddUnique(result.behaviorHints, "Would likely pass campaign, session, or execution-oriented tokens in the query string");
    }
}

UrlAnalysis AnalyzeUrl(const std::string& url)
// runs the analyze url pass and returns a focused result for the broader url analysis pipeline.
{
    UrlAnalysis result;
    result.originalUrl = url;
    result.normalizedUrl = url;

    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return result;

    UrlAnalysis originalParts;
    CrackUrlParts(url, originalParts);
    CrackUrlParts(url, result);
    result.finalUrl = ResolveRedirectChain(url, result.redirectCount, result.redirected);
    // re-crack the final hop so later fields reflect the effective destination.
    const std::string analysisTarget = (result.redirected && !result.finalUrl.empty()) ? result.finalUrl : url;
    result.effectiveHost.clear();
    CrackUrlParts(analysisTarget, result);
    result.effectiveHost = result.host;
    if (result.redirected && !originalParts.host.empty() && !result.host.empty() && ToLower(originalParts.host) != ToLower(result.host))
    {
        result.redirectsCrossHost = true;
        AddSignal(result, "Redirect chain changes the effective host");
        AddUnique(result.domainContextTags, "cross_host_redirect");
    }

    result.domain = ExtractRegisteredDomain(result.host);
    result.subdomain = ExtractSubdomain(result.host, result.domain);
    result.isIp = IsIpAddress(result.host);
    result.rawIpUrl = result.isIp;
    if (result.isIp)
    {
        result.domain.clear();
        result.subdomain.clear();
    }
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
        result.dnsResolutionFailed = result.resolvedIp.empty() && !result.host.empty() && !result.localNetworkHost;
    }

    if (!result.resolvedIp.empty())
        result.reverseDns = ReverseLookup(result.resolvedIp);

    ClassifyIpAddress(result);
    QueryIpMetadata(result);
    ClassifyProviderSignals(result);
    result.ownershipSummary = BuildOwnershipSummary(result);
    result.infrastructureClass = InferInfrastructureClass(result);
    result.exposureLabel = InferExposureLabel(result);
    result.likelyServicePurpose = InferServicePurpose(result);

    if (result.redirected)
        AddSignal(result, "URL performs redirect chaining before final destination");
    if (result.dnsResolutionFailed)
        AddSignal(result, "DNS resolution failed for the effective host");
    if (!result.https)
        AddSignal(result, "URL does not use HTTPS");
    if (result.rawIpUrl && result.likelySharedHosting)
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
