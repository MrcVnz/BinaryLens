#pragma once

// confidence scoring contracts that measure how well the current evidence supports the verdict.
#include <string>
#include <vector>

#include "core/advanced_analysis.h"

struct ConfidenceResult
{
    std::string label = "Low";
    std::string rationale = "Limited signal diversity";
    int signalCount = 0;
    int diversityScore = 0;
    std::vector<std::string> breakdown;
};

ConfidenceResult BuildConfidenceResult(const AdvancedAnalysisSummary& advanced,
                                       int riskScore,
                                       bool hasYaraMatches,
                                       bool hasReputation,
                                       bool hasValidSignature);
