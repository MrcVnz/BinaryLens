#include "core/verdict_engine.h"
#include "core/risk_engine.h"

// verdict shaping logic that turns weighted evidence into final labels and summaries.

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

// legacy callers can still build a risk object from booleans, but the final label now flows through the shared accumulator.
VerdictResult CalculateVerdict(
    bool highEntropy,
    bool suspiciousImports,
    bool unsignedFile,
    int vtMalicious,
    int vtSuspicious)
{
    RiskAccumulator risk;

    if (highEntropy)
        risk.Add(20, "High entropy sections detected");
    if (suspiciousImports)
        risk.Add(25, "Suspicious imports detected");
    if (unsignedFile)
        risk.Add(15, "File is not digitally signed");
    if (vtMalicious > 0)
        risk.Add(40, "VirusTotal malicious detections");
    if (vtSuspicious > 0)
        risk.Add(20, "VirusTotal suspicious detections");

    risk.Clamp();
    return CalculateVerdict(risk);
}

VerdictResult CalculateVerdict(const RiskAccumulator& risk)
{
    VerdictResult result;
    result.riskScore = risk.Score();
    result.reasons = risk.Reasons();
    result.verdict = VerdictLabelFromScore(result.riskScore);
    return result;
}
