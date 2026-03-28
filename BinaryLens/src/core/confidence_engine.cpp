#include "core/confidence_engine.h"

#include <algorithm>
// confidence model that tempers verdict certainty using breadth, quality, and competing benign context.

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

// certainty here is driven by independent corroboration, while strong benign context can intentionally hold confidence down.
ConfidenceResult BuildConfidenceResult(const AdvancedAnalysisSummary& advanced, int riskScore, bool hasYaraMatches, bool hasReputation, bool hasValidSignature)
{
    ConfidenceResult out;
    int diversity = 0;
    int contradictionPenalty = 0;

    if (!advanced.capabilities.empty()) { ++diversity; AddBreakdown(out, "Behavior/capability engine contributed independent signals"); }
    if (!advanced.correlationHighlights.empty()) { ++diversity; AddBreakdown(out, "Correlation engine linked multiple technical indicators"); }
    if (hasYaraMatches) { ++diversity; AddBreakdown(out, "YARA-like pattern matching added rule-backed evidence"); }
    if (!advanced.simulatedBehaviors.empty()) { ++diversity; AddBreakdown(out, "Behavior simulator produced a runtime story"); }
    if (!advanced.evasionFindings.empty()) { ++diversity; AddBreakdown(out, "Anti-evasion heuristics identified concealment clues"); }
    if (!advanced.deobfuscationFindings.empty()) { ++diversity; AddBreakdown(out, "Deobfuscation recovered additional analyst-readable content"); }
    if (hasReputation) { ++diversity; AddBreakdown(out, "Reputation data was available for comparison"); }
    if (hasValidSignature) { ++diversity; AddBreakdown(out, "Valid signature influenced confidence weighting"); }

    if (!advanced.legitimateContext.empty() && advanced.correlationHighlights.empty())
    {
        ++contradictionPenalty;
        AddBreakdown(out, "Legitimate context competes with the suspicious evidence and lowers certainty");
    }
    if (!advanced.evidenceCalibrationNotes.empty())
    {
        ++contradictionPenalty;
        AddBreakdown(out, "Context-aware calibration found reasons to dampen or reinterpret part of the evidence");
    }

    // raw signal count is useful, but diversity and contradiction control the final confidence band.
    out.signalCount = static_cast<int>(advanced.capabilities.size() + advanced.correlationHighlights.size() + advanced.yaraMatches.size() + advanced.evasionFindings.size());
    out.diversityScore = diversity;

    if (riskScore >= 70 && diversity >= 4 && contradictionPenalty == 0)
    {
        out.label = "High";
        out.rationale = "Multi-engine correlation with several independent signal types";
    }
    else if (riskScore >= 35 && diversity >= 3)
    {
        out.label = contradictionPenalty > 0 ? "Low" : "Medium";
        out.rationale = contradictionPenalty > 0
            ? "Competing legitimate context lowers confidence despite several signals"
            : "Several engines agree, but the evidence is not fully conclusive";
    }
    else
    {
        out.label = "Low";
        out.rationale = diversity <= 1 ? "Mostly single-engine or string-only evidence" : "Moderate risk with limited correlation depth";
    }
    return out;
}
