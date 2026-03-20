#include "core/verdict_engine.h"
// verdict shaping logic that turns weighted evidence into final labels and summaries.

// keep the label thresholds stable so reports stay comparable across runs.
std::string VerdictLabelFromScore(int score)
{
    if (score < 0)
        score = 0;
    else if (score > 100)
        score = 100;

    if (score >= 88)
        return "Highly Suspicious";

    if (score >= 70)
        return "High Risk";

    if (score >= 50)
        return "Suspicious";

    if (score >= 20)
        return "Low Risk";

    return "Likely Benign";
}

// balances score, context, and confidence modifiers before choosing the final label.
VerdictResult CalculateVerdict(
    bool highEntropy,
    bool suspiciousImports,
    bool unsignedFile,
    int vtMalicious,
    int vtSuspicious)
{
    VerdictResult result;

    // this base score is intentionally simple; deeper engines layer on top later.
    int score = 0;

    if (highEntropy)
    {
        score += 20;
        result.reasons.push_back("High entropy sections detected");
    }

    if (suspiciousImports)
    {
        score += 25;
        result.reasons.push_back("Suspicious imports detected");
    }

    if (unsignedFile)
    {
        score += 15;
        result.reasons.push_back("File is not digitally signed");
    }

    if (vtMalicious > 0)
    {
        score += 40;
        result.reasons.push_back("VirusTotal malicious detections");
    }

    if (vtSuspicious > 0)
    {
        score += 20;
        result.reasons.push_back("VirusTotal suspicious detections");
    }

    if (score > 100)
        score = 100;

    result.riskScore = score;
    result.verdict = VerdictLabelFromScore(score);

    return result;
}
