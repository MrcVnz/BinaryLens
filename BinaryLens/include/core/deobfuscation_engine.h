#pragma once

// deobfuscation heuristics for encoded, fragmented, or disguised text artifacts.
#include <string>
#include <vector>

#include "analyzers/indicator_extractor.h"

struct DeobfuscationResult
{
    std::vector<std::string> findings;
    std::vector<std::string> decodedArtifacts;
    int scoreBoost = 0;
};

DeobfuscationResult AnalyzeDeobfuscation(const std::string& searchableText, const Indicators& indicators);
