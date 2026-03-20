#include "core/plugin_engine.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
// plugin execution path for optional external rule packs and supplemental hits.

// plugin discovery and parsing helpers for optional external detection packs.
namespace
{
    std::string ToLowerCopy(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    std::string Trim(std::string value)
    {
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ' || value.back() == '\t'))
            value.pop_back();
        std::size_t start = 0;
        while (start < value.size() && (value[start] == ' ' || value[start] == '\t'))
            ++start;
        return value.substr(start);
    }
}

// plugin packs are optional, so discovery is tolerant and local-first.
std::vector<PluginMatch> RunPluginRulePackScan(const std::string& filePath, const std::string& searchableText)
{
    namespace fs = std::filesystem;
    std::vector<PluginMatch> matches;

    std::vector<fs::path> candidateRoots = {
        fs::current_path() / "plugins",
        fs::path(filePath).parent_path() / "plugins"
    };

    const std::string lower = ToLowerCopy(searchableText);
    for (const auto& root : candidateRoots)
    {
        if (!fs::exists(root) || !fs::is_directory(root))
            continue;

        for (const auto& entry : fs::directory_iterator(root))
        {
            if (!entry.is_regular_file() || entry.path().extension() != ".blp")
                continue;

            std::ifstream in(entry.path());
            if (!in)
                continue;

            std::string pluginName = entry.path().stem().string();
            std::string line;
            std::string label;
            int scoreBoost = 0;
            std::vector<std::string> requiredTokens;

            // the format stays intentionally tiny: label, score, and repeated match keys.
            while (std::getline(in, line))
            {
                line = Trim(line);
                if (line.empty() || line[0] == '#')
                    continue;
                const std::size_t pos = line.find('=');
                if (pos == std::string::npos)
                    continue;
                const std::string key = ToLowerCopy(Trim(line.substr(0, pos)));
                const std::string value = Trim(line.substr(pos + 1));
                if (key == "label")
                    label = value;
                else if (key == "score")
                    scoreBoost = std::max(0, std::atoi(value.c_str()));
                else if (key == "match")
                    requiredTokens.push_back(ToLowerCopy(value));
            }

            bool matched = !requiredTokens.empty();
            for (const auto& token : requiredTokens)
            {
                if (lower.find(token) == std::string::npos)
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
                matches.push_back({pluginName, label.empty() ? "Plugin rule pack match" : label, scoreBoost});
        }
    }

    return matches;
}
