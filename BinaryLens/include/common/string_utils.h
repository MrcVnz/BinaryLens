#pragma once

// shared string helpers used across scanners and analysis engines.
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
#include <utility>

namespace bl::common
{
    inline std::string ToLowerCopy(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    inline std::string TrimCopy(const std::string& value)
    {
        std::size_t start = 0;
        while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])))
            ++start;

        std::size_t end = value.size();
        while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])))
            --end;

        return value.substr(start, end - start);
    }

    inline bool IEquals(const std::string& left, const std::string& right)
    {
        return ToLowerCopy(left) == ToLowerCopy(right);
    }

    inline bool StartsWithIgnoreCase(const std::string& value, const std::string& prefix)
    {
        if (value.size() < prefix.size())
            return false;
        return IEquals(value.substr(0, prefix.size()), prefix);
    }

    inline bool EndsWithIgnoreCase(const std::string& value, const std::string& suffix)
    {
        if (value.size() < suffix.size())
            return false;
        return IEquals(value.substr(value.size() - suffix.size()), suffix);
    }

    inline void AddUnique(std::vector<std::string>& items, const std::string& value, std::size_t maxCount = static_cast<std::size_t>(-1))
    {
        if (value.empty() || items.size() >= maxCount)
            return;
        if (std::find(items.begin(), items.end(), value) == items.end())
            items.push_back(value);
    }
}
