#pragma once

// url parsing and reputation structures shared by network-facing analysis stages.
#include <string>
#include <vector>

struct UrlAnalysis
{
    std::string originalUrl;
    std::string normalizedUrl;
    std::string decodedUrl;

    std::string scheme;
    std::string host;
    std::string normalizedHost;
    std::string domain;
    std::string subdomain;
    std::string path;
    std::string normalizedPath;
    std::string query;
    std::string fragment;
    std::string port;

    std::string resolvedIp;
    std::string reverseDns;
    std::string provider;
    std::string organization;
    std::string asn;
    std::string country;
    std::string region;
    std::string city;
    std::string hostingType;
    std::string ipVersion;

    std::string finalUrl;
    std::string effectiveHost;
    std::string likelyFileName;
    std::string likelyPayloadType;
    std::string urlCategory;
    std::string domainTrustLabel;
    std::string impersonatedBrand;

    int redirectCount = 0;
    int hostLabelCount = 0;
    int pathSegmentCount = 0;
    int queryParameterCount = 0;
    int longestQueryValueLength = 0;
    int suspiciousKeywordHits = 0;

    bool isIp = false;
    bool usesShortener = false;
    bool suspiciousTld = false;
    bool punycode = false;
    bool suspiciousQuery = false;
    bool redirected = false;
    bool https = false;
    bool rawIpUrl = false;
    bool hasQuery = false;
    bool likelySharedHosting = false;
    bool likelyExclusiveIp = false;

    bool isPrivateIp = false;
    bool isReservedIp = false;
    bool hasExcessiveSubdomains = false;
    bool suspiciousPath = false;
    bool suspiciousKeywords = false;
    bool suspiciousEncodedSegments = false;
    bool loginBrandLure = false;
    bool cloudOrCdnInfrastructure = false;
    bool knownSafeProvider = false;
    bool likelyDynamicDns = false;
    bool providerLookupSucceeded = false;

    bool nonStandardPort = false;
    bool suspiciousPort = false;
    bool hasUserInfo = false;
    bool hasAtSymbol = false;
    bool doubleEncoded = false;
    bool longHostName = false;
    bool longQueryBlob = false;
    bool likelyExecutableDownload = false;
    bool likelyArchiveDownload = false;
    bool likelyScriptDownload = false;
    bool suspiciousFileExtension = false;
    bool knownSafeDomain = false;
    bool likelyBrandImpersonation = false;
    bool directFileLink = false;
    bool likelyCredentialHarvest = false;
    bool likelyPayloadDelivery = false;

    std::vector<std::string> securitySignals;
    std::vector<std::string> normalizedIndicators;
    std::vector<std::string> domainContextTags;
    std::vector<std::string> behaviorHints;
};

UrlAnalysis AnalyzeUrl(const std::string& url);
