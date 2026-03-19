#include "core/confidence_engine.h"

#include <algorithm>
// confidence model that tempers verdict certainty using breadth and quality of evidence.

// confidence helpers that reward corroboration and penalize thin or purely contextual evidence.
namespace
{
    void AddBreakdown(ConfidenceResult& out, const std::string& value)
    {
        if (value.empty())
            return;
        if (std::find(out.breakdown.begin(), out.breakdown.end(), value) == out.breakdown.end())
            out.breakdown.push_back(value);
    }
}

// derives certainty from evidence breadth, consistency, and strength instead of raw score alone.
ConfidenceResult BuildConfidenceResult(const AdvancedAnalysisSummary& advanced, int riskScore, bool hasYaraMatches, bool hasReputation, bool hasValidSignature)
{
    ConfidenceResult out;
    int diversity = 0;
    if (!advanced.capabilities.empty()) { ++diversity; AddBreakdown(out, "Behavior/capability engine contributed independent signals"); }
    if (!advanced.correlationHighlights.empty()) { ++diversity; AddBreakdown(out, "Correlation engine linked multiple technical indicators"); }
    if (hasYaraMatches) { ++diversity; AddBreakdown(out, "YARA-like pattern matching added rule-backed evidence"); }
    if (!advanced.simulatedBehaviors.empty()) { ++diversity; AddBreakdown(out, "Behavior simulator produced a runtime story"); }
    if (!advanced.evasionFindings.empty()) { ++diversity; AddBreakdown(out, "Anti-evasion heuristics identified concealment clues"); }
    if (hasReputation) { ++diversity; AddBreakdown(out, "Reputation data was available for comparison"); }
    if (hasValidSignature) { ++diversity; AddBreakdown(out, "Valid signature influenced confidence weighting"); }

    out.signalCount = static_cast<int>(advanced.capabilities.size() + advanced.correlationHighlights.size() + advanced.yaraMatches.size() + advanced.evasionFindings.size());
    out.diversityScore = diversity;

    if (riskScore >= 70 && diversity >= 4)
    {
        out.label = "High";
        out.rationale = "Multi-engine correlation with several independent signal types";
    }
    else if (riskScore >= 35 && diversity >= 3)
    {
        out.label = "Medium";
        out.rationale = "Several engines agree, but the evidence is not fully conclusive";
    }
    else
    {
        out.label = "Low";
        out.rationale = diversity <= 1 ? "Mostly single-engine or string-only evidence" : "Moderate risk with limited correlation depth";
    }
    return out;
}
