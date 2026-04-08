#include "core/risk_engine.h"

#include <algorithm>

// score accumulator implementation with clamping and explanation tracking.

// adds bounded score deltas while preserving a readable reason trail.
// each addition carries its own reason so later report sections can explain the score path.
void RiskAccumulator::Add(int delta, const std::string& reason)
// adds this detail through one gate so duplicate or noisy output stays under control.
{
    score_ += delta;
    // deduping reasons here keeps later report sections from having to clean the same text again.
    if (!reason.empty() && std::find(reasons_.begin(), reasons_.end(), reason) == reasons_.end())
        reasons_.push_back(reason);
}

// seeding keeps the old reason trail when a prior verdict already exists.
void RiskAccumulator::Seed(int score, const std::vector<std::string>& reasons)
// keeps the seed step local to this risk scoring file so callers can stay focused on intent.
{
    score_ = score;
    reasons_.clear();
    // seeding respects uniqueness too because upstream callers may already carry merged reason lists.
    for (const auto& reason : reasons)
    {
        if (!reason.empty() && std::find(reasons_.begin(), reasons_.end(), reason) == reasons_.end())
            reasons_.push_back(reason);
    }
}

// score reads stay trivial because all shaping happens through add, seed, and clamp.
int RiskAccumulator::Score() const
// applies the narrow score rules here and leaves final weighting to the caller.
{
    return score_;
}

// reasons are returned by value here because callers usually need their own copy for formatting.
std::vector<std::string> RiskAccumulator::Reasons() const
// keeps the reasons step local to this risk scoring file so callers can stay focused on intent.
{
    return reasons_;
}

// keeps the public score inside the expected range after all adjustments.
void RiskAccumulator::Clamp()
// keeps the clamp step local to this risk scoring file so callers can stay focused on intent.
{
    // clamp late so intermediate adjustments can stay simple and additive.
    if (score_ < 0)
        score_ = 0;
    else if (score_ > 100)
        score_ = 100;
}
