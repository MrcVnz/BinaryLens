#pragma once

// ioc enrichment results built from extracted network, filesystem, and registry artifacts.
#include <string>
#include <vector>

#include "analyzers/indicator_extractor.h"

struct IocIntelligenceFinding
{
    std::string artifact;
    std::string classification;
    std::string rationale;
};

struct IocIntelligenceResult
{
    std::vector<IocIntelligenceFinding> findings;
    std::vector<std::string> summary;
};

IocIntelligenceResult AnalyzeIocIntelligence(const Indicators& indicators);
