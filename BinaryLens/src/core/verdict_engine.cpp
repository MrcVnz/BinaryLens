#include "core/verdict_engine.h"
#include "core/risk_engine.h"

// verdict shaping logic that turns weighted evidence into final labels and summaries.

// one place owns the score-to-label mapping so every ui and export path stays aligned.
std::string VerdictLabelFromScore(int score)
// applies the narrow verdict label from score rules here and leaves final weighting to the caller.
{
    if (score < 0)
        score = 0;
    else if (score > 100)
        score = 100;

    // thresholds stay intentionally coarse because the detailed reasoning lives in the risk trail.
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
// this overload keeps older call sites working while newer code moves through the shared risk accumulator.
VerdictResult CalculateVerdict(
    bool highEntropy,
    bool suspiciousImports,
    bool unsignedFile,
    int vtMalicious,
    int vtSuspicious)
// keeps the calculate verdict step local to this verdict shaping file so callers can stay focused on intent.
{
    // these booleans only seed the accumulator; clamping and final labeling still happen in one place.
    RiskAccumulator risk;

    // these seeds preserve older call sites while newer code supplies a richer accumulator directly.
    if (highEntropy)
        risk.Add(20, "High entropy sections detected");
    if (suspiciousImports)
        risk.Add(25, "Suspicious imports detected");
    if (unsignedFile)
        risk.Add(15, "File is not digitally signed");
    // reputation is seeded here for legacy callers, but the shared pipeline can still override the overall tone later.
    if (vtMalicious > 0)
        risk.Add(40, "VirusTotal malicious detections");
    if (vtSuspicious > 0)
        risk.Add(20, "VirusTotal suspicious detections");

    risk.Clamp();
    return CalculateVerdict(risk);
}

// the accumulator overload is the canonical path used by the newer analysis pipeline.
VerdictResult CalculateVerdict(const RiskAccumulator& risk)
// keeps the calculate verdict step local to this verdict shaping file so callers can stay focused on intent.
{
    VerdictResult result;
    // the final verdict object stays thin because explanation already lives inside the accumulator.
    result.riskScore = risk.Score();
    result.reasons = risk.Reasons();
    // label selection stays last so every upstream adjustment is already reflected in the final score.
    result.verdict = VerdictLabelFromScore(result.riskScore);
    return result;
}
