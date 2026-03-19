#pragma once

// lightweight yara-like scanning contracts used without a full external dependency.
#include <string>
#include <vector>

struct YaraRuleMatch
{
    std::string ruleName;
    std::vector<std::string> matchedTokens;
    int scoreBoost = 0;
    std::string conditionSummary;
};

struct YaraScanResult
{
    bool loadedAnyRule = false;
    bool usedBuiltInFallback = false;
    int rulesLoaded = 0;
    std::vector<YaraRuleMatch> matches;
    std::vector<std::string> notes;
};

YaraScanResult RunLightweightYaraScan(const std::string& filePath, const std::string& searchableText);
