#pragma once

// plugin scan contracts for external rule packs and extensible detection logic.
#include <string>
#include <vector>

struct PluginMatch
{
    std::string pluginName;
    std::string label;
    int scoreBoost = 0;
};

std::vector<PluginMatch> RunPluginRulePackScan(const std::string& filePath, const std::string& searchableText);
