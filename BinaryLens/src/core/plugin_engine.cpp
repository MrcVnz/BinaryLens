#include "core/plugin_engine.h"
#include "common/runtime_paths.h"
#include "common/string_utils.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>

// plugin execution path for optional external rule packs and supplemental hits.

namespace
{
    std::string Trim(std::string value)
    {
        return bl::common::TrimCopy(value);
    }
}

// plugin packs are optional, but they now load only from trusted application-controlled directories.
std::vector<PluginMatch> RunPluginRulePackScan(const std::string& filePath, const std::string& searchableText)
{
    namespace fs = std::filesystem;
    (void)filePath;
    std::vector<PluginMatch> matches;

    const std::string lower = bl::common::ToLowerCopy(searchableText);
    for (const auto& root : bl::common::GetTrustedPluginDirectories())
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

            while (std::getline(in, line))
            {
                line = Trim(line);
                if (line.empty() || line[0] == '#')
                    continue;
                const std::size_t pos = line.find('=');
                if (pos == std::string::npos)
                    continue;
                const std::string key = bl::common::ToLowerCopy(Trim(line.substr(0, pos)));
                const std::string value = Trim(line.substr(pos + 1));
                if (key == "label")
                    label = value;
                else if (key == "score")
                    scoreBoost = std::max(0, std::atoi(value.c_str()));
                else if (key == "match")
                    requiredTokens.push_back(bl::common::ToLowerCopy(value));
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
