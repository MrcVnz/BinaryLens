#pragma once

// url normalization and remote metadata interfaces used before deeper reputation checks.
#include <cstdint>
#include <string>

struct URLReputationResult
{
    bool success = false;
    int httpStatusCode = 0;

    int maliciousDetections = 0;
    int suspiciousDetections = 0;
    int harmlessDetections = 0;
    int undetectedDetections = 0;

    std::string summary;
    std::string rawResponse;
};

struct URLPreflightResult
{
    bool success = false;
    int httpStatusCode = 0;
    bool followedRedirect = false;

    std::string finalUrl;
    std::string contentType;
    std::string contentDisposition;
    std::string serverHeader;
    std::string suggestedFileName;

    std::uint64_t contentLength = 0;
    bool likelyHtml = false;
    bool likelyDownload = false;
    bool likelyScript = false;
    bool likelyArchive = false;
    bool likelyExecutable = false;

    std::string summary;
};

bool LooksLikeURL(const std::string& input);
std::string NormalizeURL(const std::string& input);
URLReputationResult QueryVirusTotalURL(const std::string& url, const std::string& apiKey);
URLPreflightResult FetchURLPreflight(const std::string& url);
