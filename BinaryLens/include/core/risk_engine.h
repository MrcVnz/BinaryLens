#pragma once

// bounded score accumulator used to keep risk deltas and reasons synchronized.
#include <string>
#include <vector>

struct RiskContribution
{
    int delta = 0;
    std::string reason;
};

class RiskAccumulator
{
public:
    void Add(int delta, const std::string& reason);
    void Seed(int score, const std::vector<std::string>& reasons);
    int Score() const;
    std::vector<std::string> Reasons() const;
    void Clamp();

private:
    int score_ = 0;
    std::vector<std::string> reasons_;
};
