#pragma once

// api access helpers for configuration loading and virustotal communication.
#include <string>

struct ReputationResult
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

std::string LoadVTApiKey();

ReputationResult QueryVirusTotalByHash(const std::string& sha256, const std::string& apiKey);
ReputationResult QueryVirusTotalUrl(const std::string& url, const std::string& apiKey);
ReputationResult QueryVirusTotalIp(const std::string& ip, const std::string& apiKey);
