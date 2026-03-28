
#include "core/yara_engine.h"
#include "common/runtime_paths.h"
#include "common/string_utils.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <vector>
// embedded yara-style rule loader and evaluator used for portable signature matching.

// rule parsing helpers for strings, modifiers, and simplified condition evaluation.
namespace
{
    struct TokenPattern
    {
        std::string identifier;
        std::string value;
        bool nocase = false;
    };

    struct ParsedRule
    {
        std::string name;
        std::vector<TokenPattern> patterns;
        std::string condition;
        int scoreBoost = 8;
        std::string description;
    };

    std::string ToLowerCopy(std::string value)
    {
        return bl::common::ToLowerCopy(std::move(value));
    }

    std::string TrimCopy(const std::string& value)
    {
        const std::size_t start = value.find_first_not_of(" \t\r\n");
        if (start == std::string::npos)
            return {};
        const std::size_t end = value.find_last_not_of(" \t\r\n");
        return value.substr(start, end - start + 1);
    }

    bool StartsWithInsensitive(const std::string& value, const std::string& prefix)
    {
        if (value.size() < prefix.size())
            return false;
        return ToLowerCopy(value.substr(0, prefix.size())) == ToLowerCopy(prefix);
    }

    void AddUnique(std::vector<std::string>& items, const std::string& value)
    {
        bl::common::AddUnique(items, value);
    }

    std::size_t CountOccurrences(const std::string& haystack, const std::string& needle)
    {
        if (needle.empty() || haystack.empty())
            return 0;
        std::size_t count = 0;
        std::size_t pos = 0;
        while ((pos = haystack.find(needle, pos)) != std::string::npos)
        {
            ++count;
            pos += needle.size();
        }
        return count;
    }

    // built-ins cover common tradecraft even when no external rules are present.
    std::vector<ParsedRule> BuiltInRules()
    {
        return {
            {
                "Suspicious_PowerShell_Loader",
                {
                    {"$ps", "powershell", true},
                    {"$enc", "-enc", true},
                    {"$iex", "invoke-expression", true},
                    {"$dl1", "downloadstring", true},
                    {"$dl2", "invoke-webrequest", true}
                },
                "($ps and ($enc or $iex) and (1 of ($dl1,$dl2))) or 3 of them",
                14,
                "Generic PowerShell loader or stager pattern"
            },
            {
                "Credential_Stealer_Generic",
                {
                    {"$login", "login data", true},
                    {"$cookies", "cookies.sqlite", true},
                    {"$dpapi", "cryptunprotectdata", true},
                    {"$vault", "vaultcmd", true},
                    {"$lsass", "lsass", true}
                },
                "2 of them",
                16,
                "Generic browser or credential stealing references"
            },
            {
                "Anti_Debug_Generic",
                {
                    {"$idp", "isdebuggerpresent", true},
                    {"$crdp", "checkremotedebuggerpresent", true},
                    {"$ntq", "ntqueryinformationprocess", true},
                    {"$dbg", "outputdebugstring", true}
                },
                "2 of them",
                10,
                "Generic anti-debug API clustering"
            },
            {
                "Ransomware_Command_Pattern",
                {
                    {"$vss", "vssadmin delete shadows", true},
                    {"$bcd", "bcdedit /set", true},
                    {"$wb", "wbadmin delete catalog", true},
                    {"$wevt", "wevtutil cl", true}
                },
                "2 of them",
                18,
                "Ransomware-like recovery inhibition commands"
            },
            {
                "Process_Injection_Generic",
                {
                    {"$wpm", "writeprocessmemory", true},
                    {"$crt", "createremotethread", true},
                    {"$vae", "virtualallocex", true},
                    {"$qapc", "queueuserapc", true}
                },
                "2 of them",
                16,
                "Common process injection API combination"
            }
        };
    }

    std::vector<std::string> SplitIdentifiers(const std::string& text)
    {
        std::vector<std::string> out;
        std::string current;
        for (char ch : text)
        {
            if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '$' || ch == '_' || ch == '#')
            {
                current.push_back(ch);
            }
            else
            {
                if (!current.empty())
                {
                    out.push_back(current);
                    current.clear();
                }
            }
        }
        if (!current.empty())
            out.push_back(current);
        return out;
    }

    std::vector<std::string> SplitCsvIdentifiers(const std::string& text)
    {
        std::vector<std::string> out;
        std::string current;
        for (char ch : text)
        {
            if (ch == ',')
            {
                const std::string item = TrimCopy(current);
                if (!item.empty())
                    out.push_back(item);
                current.clear();
            }
            else
            {
                current.push_back(ch);
            }
        }
        const std::string tail = TrimCopy(current);
        if (!tail.empty())
            out.push_back(tail);
        return out;
    }

    // accept a small yara-like subset so local rules stay portable and dependency-free.
    std::vector<ParsedRule> LoadRulesFromDirectory(const std::filesystem::path& dir)
    {
        std::vector<ParsedRule> out;
        if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir))
            return out;

        for (const auto& entry : std::filesystem::directory_iterator(dir))
        {
            if (!entry.is_regular_file())
                continue;
            const std::string ext = ToLowerCopy(entry.path().extension().string());
            if (ext != ".yar" && ext != ".yara")
                continue;

            std::ifstream in(entry.path());
            if (!in)
                continue;

            ParsedRule current;
            bool insideRule = false;
            bool insideStrings = false;
            bool insideCondition = false;
            bool insideMeta = false;
            std::string line;
            std::ostringstream condition;
            // the loader is permissive on whitespace but strict on required sections.
            while (std::getline(in, line))
            {
                const std::string trimmed = TrimCopy(line);
                const std::string lower = ToLowerCopy(trimmed);
                if (trimmed.empty() || StartsWithInsensitive(trimmed, "//"))
                    continue;

                if (StartsWithInsensitive(lower, "rule "))
                {
                    if (insideRule && !current.name.empty() && !current.patterns.empty())
                    {
                        if (current.condition.empty())
                            current.condition = "all of them";
                        out.push_back(current);
                    }
                    current = {};
                    condition.str("");
                    condition.clear();
                    insideRule = true;
                    insideStrings = false;
                    insideCondition = false;
                    insideMeta = false;
                    std::istringstream iss(trimmed);
                    std::string tmp;
                    iss >> tmp >> current.name;
                    const std::size_t brace = current.name.find('{');
                    if (brace != std::string::npos)
                        current.name = current.name.substr(0, brace);
                    continue;
                }
                if (!insideRule)
                    continue;

                if (StartsWithInsensitive(lower, "meta:"))
                {
                    insideMeta = true;
                    insideStrings = false;
                    insideCondition = false;
                    continue;
                }
                if (StartsWithInsensitive(lower, "strings:"))
                {
                    insideStrings = true;
                    insideMeta = false;
                    insideCondition = false;
                    continue;
                }
                if (StartsWithInsensitive(lower, "condition:"))
                {
                    insideCondition = true;
                    insideMeta = false;
                    insideStrings = false;
                    continue;
                }

                if (trimmed.find('}') != std::string::npos)
                {
                    if (insideCondition)
                        current.condition = TrimCopy(condition.str());
                    if (!current.name.empty() && !current.patterns.empty())
                    {
                        if (current.condition.empty())
                            current.condition = "all of them";
                        out.push_back(current);
                    }
                    current = {};
                    condition.str("");
                    condition.clear();
                    insideRule = false;
                    insideStrings = false;
                    insideCondition = false;
                    insideMeta = false;
                    continue;
                }

                // only a few meta keys are consumed because the report uses a compact rule model.
                if (insideMeta)
                {
                    const std::size_t eq = trimmed.find('=');
                    if (eq != std::string::npos)
                    {
                        const std::string key = TrimCopy(trimmed.substr(0, eq));
                        const std::string rawValue = TrimCopy(trimmed.substr(eq + 1));
                        if (ToLowerCopy(key) == "score_boost")
                        {
                            try { current.scoreBoost = std::max(1, std::stoi(rawValue)); }
                            catch (...) {}
                        }
                        else if (ToLowerCopy(key) == "description")
                        {
                            if (rawValue.size() >= 2 && rawValue.front() == '"' && rawValue.back() == '"')
                                current.description = rawValue.substr(1, rawValue.size() - 2);
                        }
                    }
                    continue;
                }

                if (insideStrings)
                {
                    const std::size_t eq = trimmed.find('=');
                    const std::size_t quote1 = trimmed.find('"');
                    if (eq != std::string::npos && quote1 != std::string::npos)
                    {
                        const std::string identifier = TrimCopy(trimmed.substr(0, eq));
                        const std::size_t quote2 = trimmed.find('"', quote1 + 1);
                        if (quote2 != std::string::npos && quote2 > quote1 + 1)
                        {
                            TokenPattern pattern;
                            pattern.identifier = identifier;
                            pattern.value = trimmed.substr(quote1 + 1, quote2 - quote1 - 1);
                            const std::string suffix = ToLowerCopy(trimmed.substr(quote2 + 1));
                            pattern.nocase = suffix.find("nocase") != std::string::npos;
                            current.patterns.push_back(pattern);
                        }
                    }
                    continue;
                }

                if (insideCondition)
                {
                    if (!condition.str().empty())
                        condition << ' ';
                    condition << trimmed;
                }
            }

            if (insideRule && !current.name.empty() && !current.patterns.empty())
            {
                if (current.condition.empty())
                    current.condition = TrimCopy(condition.str());
                if (current.condition.empty())
                    current.condition = "all of them";
                out.push_back(current);
            }
        }
        return out;
    }

    struct EvaluationContext
    {
        std::unordered_map<std::string, bool> matched;
        std::unordered_map<std::string, std::size_t> counts;
        std::vector<std::string> allIdentifiers;
        std::uintmax_t fileSizeBytes = 0;
    };

    // parse a narrow condition grammar instead of full yara syntax.
    struct ConditionParser
    {
        std::vector<std::string> tokens;
        std::size_t index = 0;
        const EvaluationContext& ctx;

        explicit ConditionParser(std::vector<std::string> t, const EvaluationContext& c) : tokens(std::move(t)), ctx(c) {}

        bool End() const { return index >= tokens.size(); }
        std::string Peek() const { return End() ? std::string() : ToLowerCopy(tokens[index]); }
        std::string ConsumeRaw() { return End() ? std::string() : tokens[index++]; }
        std::string Consume() { return ToLowerCopy(ConsumeRaw()); }

        // precedence stays simple: or above and above unary or primary checks.
        bool ParseExpression() { return ParseOr(); }

        bool ParseOr()
        {
            bool value = ParseAnd();
            while (!End() && Peek() == "or")
            {
                Consume();
                value = value || ParseAnd();
            }
            return value;
        }

        bool ParseAnd()
        {
            bool value = ParseUnary();
            while (!End() && Peek() == "and")
            {
                Consume();
                value = value && ParseUnary();
            }
            return value;
        }

        bool ParseUnary()
        {
            if (!End() && Peek() == "not")
            {
                Consume();
                return !ParseUnary();
            }
            return ParsePrimary();
        }

        static std::optional<std::uintmax_t> ParseSizeLiteral(const std::string& raw)
        {
            std::string lower = ToLowerCopy(raw);
            if (lower.empty())
                return std::nullopt;
            std::uintmax_t factor = 1;
            if (lower.size() > 2 && lower.substr(lower.size() - 2) == "kb")
            {
                factor = 1024;
                lower.resize(lower.size() - 2);
            }
            else if (lower.size() > 2 && lower.substr(lower.size() - 2) == "mb")
            {
                factor = 1024ull * 1024ull;
                lower.resize(lower.size() - 2);
            }
            else if (lower.size() > 2 && lower.substr(lower.size() - 2) == "gb")
            {
                factor = 1024ull * 1024ull * 1024ull;
                lower.resize(lower.size() - 2);
            }
            lower = TrimCopy(lower);
            try
            {
                return static_cast<std::uintmax_t>(std::stoull(lower)) * factor;
            }
            catch (...)
            {
                return std::nullopt;
            }
        }

        bool CompareCount(std::size_t left, const std::string& op, std::size_t right) const
        {
            if (op == ">=") return left >= right;
            if (op == "<=") return left <= right;
            if (op == ">") return left > right;
            if (op == "<") return left < right;
            if (op == "==" || op == "=") return left == right;
            return false;
        }

        bool ParseIdentifierListInsideParens(std::vector<std::string>& ids)
        {
            if (End() || Peek() != "(")
                return false;
            Consume();
            while (!End())
            {
                const std::string raw = ConsumeRaw();
                const std::string lower = ToLowerCopy(raw);
                if (lower == ")")
                    return true;
                if (lower == ",")
                    continue;
                ids.push_back(raw);
            }
            return false;
        }

        // support both "of them" and explicit identifier lists.
        bool EvaluateOf(std::size_t requiredCount)
        {
            if (End())
                return false;

            if (Peek() == "them")
            {
                Consume();
                std::size_t matchedCount = 0;
                for (const auto& id : ctx.allIdentifiers)
                {
                    auto it = ctx.matched.find(id);
                    if (it != ctx.matched.end() && it->second)
                        ++matchedCount;
                }
                return matchedCount >= requiredCount;
            }

            std::vector<std::string> ids;
            if (!ParseIdentifierListInsideParens(ids))
                return false;

            std::size_t matchedCount = 0;
            for (const auto& id : ids)
            {
                auto it = ctx.matched.find(id);
                if (it != ctx.matched.end() && it->second)
                    ++matchedCount;
            }
            return matchedCount >= requiredCount;
        }

        bool ParsePrimary()
        {
            if (End())
                return false;

            if (Peek() == "(")
            {
                Consume();
                const bool value = ParseExpression();
                if (!End() && Peek() == ")")
                    Consume();
                return value;
            }

            const std::string raw = ConsumeRaw();
            const std::string token = ToLowerCopy(raw);

            if (token == "all")
            {
                if (!End() && Peek() == "of")
                    Consume();
                if (Peek() == "them")
                    return EvaluateOf(ctx.allIdentifiers.size());
                std::vector<std::string> ids;
                if (!ParseIdentifierListInsideParens(ids))
                    return false;
                return EvaluateIdentifierSet(ids, ids.size());
            }
            if (token == "any")
            {
                if (!End() && Peek() == "of")
                    Consume();
                return EvaluateOf(1);
            }
            if (std::all_of(token.begin(), token.end(), [](unsigned char c){ return std::isdigit(c); }))
            {
                const std::size_t n = static_cast<std::size_t>(std::stoul(token));
                if (!End() && Peek() == "of")
                    Consume();
                return EvaluateOf(n);
            }
            if (!token.empty() && token[0] == '#')
            {
                const std::string ident = raw.substr(1);
                const std::size_t left = ctx.counts.count(ident) ? ctx.counts.at(ident) : 0;
                if (End())
                    return left > 0;
                const std::string op = Peek();
                if (op == ">=" || op == "<=" || op == ">" || op == "<" || op == "==" || op == "=")
                {
                    Consume();
                    if (End())
                        return false;
                    try
                    {
                        const std::size_t right = static_cast<std::size_t>(std::stoul(ConsumeRaw()));
                        return CompareCount(left, op, right);
                    }
                    catch (...)
                    {
                        return false;
                    }
                }
                return left > 0;
            }
            if (token == "filesize")
            {
                if (End())
                    return false;
                const std::string op = Consume();
                if (End())
                    return false;
                const std::string sizeRaw = ConsumeRaw();
                const auto target = ParseSizeLiteral(sizeRaw);
                if (!target)
                    return false;
                return CompareCount(static_cast<std::size_t>(ctx.fileSizeBytes), op, static_cast<std::size_t>(*target));
            }
            if (!raw.empty() && raw[0] == '$')
            {
                auto it = ctx.matched.find(raw);
                return it != ctx.matched.end() && it->second;
            }
            return false;
        }

        bool EvaluateIdentifierSet(const std::vector<std::string>& ids, std::size_t requiredCount) const
        {
            std::size_t matchedCount = 0;
            for (const auto& id : ids)
            {
                auto it = ctx.matched.find(id);
                if (it != ctx.matched.end() && it->second)
                    ++matchedCount;
            }
            return matchedCount >= requiredCount;
        }
    };

    std::vector<std::string> TokenizeCondition(const std::string& condition)
    {
        std::vector<std::string> tokens;
        std::string current;
        auto flush = [&]() {
            if (!current.empty())
            {
                tokens.push_back(current);
                current.clear();
            }
        };

        for (std::size_t i = 0; i < condition.size(); ++i)
        {
            const char ch = condition[i];
            if (std::isspace(static_cast<unsigned char>(ch)))
            {
                flush();
                continue;
            }
            if (ch == '(' || ch == ')' || ch == ',')
            {
                flush();
                tokens.emplace_back(1, ch);
                continue;
            }
            if (ch == '>' || ch == '<' || ch == '=')
            {
                flush();
                std::string op(1, ch);
                if (i + 1 < condition.size() && condition[i + 1] == '=')
                {
                    op.push_back('=');
                    ++i;
                }
                tokens.push_back(op);
                continue;
            }
            current.push_back(ch);
        }
        flush();
        return tokens;
    }

    // precompute match counts once so condition evaluation stays cheap.
    EvaluationContext BuildEvaluationContext(const ParsedRule& rule, const std::string& searchableText, std::uintmax_t fileSizeBytes)
    {
        EvaluationContext ctx;
        ctx.fileSizeBytes = fileSizeBytes;
        const std::string lower = ToLowerCopy(searchableText);
        for (const auto& pattern : rule.patterns)
        {
            const std::string normalizedNeedle = pattern.nocase ? ToLowerCopy(pattern.value) : pattern.value;
            const std::string& haystack = pattern.nocase ? lower : searchableText;
            const std::size_t hits = CountOccurrences(haystack, normalizedNeedle);
            ctx.matched[pattern.identifier] = hits > 0;
            ctx.counts[pattern.identifier] = hits;
            ctx.allIdentifiers.push_back(pattern.identifier);
        }
        return ctx;
    }

    bool EvaluateRuleCondition(const ParsedRule& rule, const EvaluationContext& ctx)
    {
        const std::vector<std::string> tokens = TokenizeCondition(rule.condition.empty() ? "all of them" : rule.condition);
        if (tokens.empty())
        {
            std::size_t matchedCount = 0;
            for (const auto& id : ctx.allIdentifiers)
            {
                auto it = ctx.matched.find(id);
                if (it != ctx.matched.end() && it->second)
                    ++matchedCount;
            }
            return matchedCount == ctx.allIdentifiers.size();
        }
        ConditionParser parser(tokens, ctx);
        return parser.ParseExpression();
    }
}

// loads local rules, evaluates string hits, and applies rule conditions against the current sample.
YaraScanResult RunLightweightYaraScan(const std::string& filePath, const std::string& searchableText)
{
    YaraScanResult result;
    std::filesystem::path inputPath(filePath);

    std::vector<ParsedRule> rules;
    for (const auto& rulesDir : bl::common::GetTrustedRuleDirectories())
    {
        rules = LoadRulesFromDirectory(rulesDir);
        if (!rules.empty())
        {
            AddUnique(result.notes, "Loaded lightweight YARA rules from trusted disk location");
            break;
        }
    }

    if (rules.empty())
    {
        rules = BuiltInRules();
        result.usedBuiltInFallback = true;
        AddUnique(result.notes, "Using built-in lightweight YARA fallback rules");
    }

    result.rulesLoaded = static_cast<int>(rules.size());
    result.loadedAnyRule = !rules.empty();
    std::uintmax_t fileSizeBytes = 0;
    try
    {
        fileSizeBytes = std::filesystem::exists(inputPath) ? std::filesystem::file_size(inputPath) : 0;
    }
    catch (...) {}

    for (const auto& rule : rules)
    {
        const EvaluationContext ctx = BuildEvaluationContext(rule, searchableText, fileSizeBytes);
        if (!EvaluateRuleCondition(rule, ctx))
            continue;

        YaraRuleMatch match;
        match.ruleName = rule.name;
        match.scoreBoost = rule.scoreBoost;
        match.conditionSummary = rule.condition;
        for (const auto& pattern : rule.patterns)
        {
            auto it = ctx.matched.find(pattern.identifier);
            if (it != ctx.matched.end() && it->second)
                AddUnique(match.matchedTokens, pattern.value);
        }
        result.matches.push_back(match);
    }
    return result;
}
