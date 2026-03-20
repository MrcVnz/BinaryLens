#include "core/risk_engine.h"

#include <algorithm>
// score accumulator implementation with clamping and explanation tracking.

// adds bounded score deltas while preserving a readable reason trail.
void RiskAccumulator::Add(int delta, const std::string& reason)
{
    score_ += delta;
    if (!reason.empty() && std::find(reasons_.begin(), reasons_.end(), reason) == reasons_.end())
        reasons_.push_back(reason);
}

// seeding keeps the old reason trail when a prior verdict already exists.
void RiskAccumulator::Seed(int score, const std::vector<std::string>& reasons)
{
    score_ = score;
    reasons_.clear();
    for (const auto& reason : reasons)
    {
        if (!reason.empty() && std::find(reasons_.begin(), reasons_.end(), reason) == reasons_.end())
            reasons_.push_back(reason);
    }
}

int RiskAccumulator::Score() const
{
    return score_;
}

std::vector<std::string> RiskAccumulator::Reasons() const
{
    return reasons_;
}

// keeps the public score inside the expected range after all adjustments.
void RiskAccumulator::Clamp()
{
    if (score_ < 0)
        score_ = 0;
    else if (score_ > 100)
        score_ = 100;
}
