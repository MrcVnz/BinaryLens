#pragma once

// string extraction results and indicator categories reused across file and text pipelines.
#include <string>
#include <vector>

// extracted artifacts are reused across most downstream engines.
struct Indicators
{
    std::vector<std::string> urls;
    std::vector<std::string> ips;
    std::vector<std::string> domains;
    std::vector<std::string> emails;
    std::vector<std::string> filePaths;
    std::vector<std::string> registryKeys;
    std::vector<std::string> suspiciousCommands;
    std::vector<std::string> base64Blobs;
    std::vector<std::string> embeddedLibraries;
    std::vector<std::string> trustReferences;
    std::vector<std::string> analysisToolReferences;
    std::vector<std::string> behaviorHighlights;

    std::vector<std::string> matchedRules;

    unsigned int downloaderEvidenceCount = 0;
    unsigned int ransomwareEvidenceCount = 0;
    unsigned int spywareEvidenceCount = 0;
    unsigned int credentialTheftEvidenceCount = 0;
    unsigned int keyloggingEvidenceCount = 0;
    unsigned int persistenceEvidenceCount = 0;
    unsigned int injectionEvidenceCount = 0;
    unsigned int evasionEvidenceCount = 0;

    bool hasSecurityAnalysisContext = false;
    bool hasDownloaderTraits = false;
    bool hasRansomwareTraits = false;
    bool hasSpywareTraits = false;
    bool hasCredentialTheftTraits = false;
    bool hasKeyloggingTraits = false;
    bool hasPersistenceTraits = false;
    bool hasInjectionTraits = false;
    bool hasEvasionTraits = false;
    bool hasInstallerTraits = false;

    unsigned int asciiStringCount = 0;
    unsigned int unicodeStringCount = 0;
    unsigned int filteredNoiseCount = 0;
};

Indicators ExtractIndicators(const std::string& filePath);

Indicators ExtractIndicatorsFromText(const std::string& searchableText);
