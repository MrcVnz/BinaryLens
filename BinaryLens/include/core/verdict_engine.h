#pragma once

// final verdict calculation contracts that convert score and context into user-facing labels.
#include <string>
#include <vector>

class RiskAccumulator;

struct VerdictResult
{
    int riskScore = 0;
    std::string verdict;
    std::vector<std::string> reasons;
};

VerdictResult CalculateVerdict(
    bool highEntropy,
    bool suspiciousImports,
    bool unsignedFile,
    int vtMalicious,
    int vtSuspicious
);
VerdictResult CalculateVerdict(const RiskAccumulator& risk);
std::string VerdictLabelFromScore(int score);
