#include "core/deobfuscation_engine.h"

#include <algorithm>
#include <cctype>
// encoded-string and obfuscation heuristics used to recover stronger indicators.

// helpers for spotting encoded chunks, string fragmentation, and suspicious decoding patterns.
namespace
{
    void AddUnique(std::vector<std::string>& out, const std::string& value, std::size_t maxItems = 8)
    {
        if (value.empty() || out.size() >= maxItems)
            return;
        if (std::find(out.begin(), out.end(), value) == out.end())
            out.push_back(value);
    }

    std::string Trim(const std::string& value)
    {
        std::size_t start = 0;
        while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])))
            ++start;
        std::size_t end = value.size();
        while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])))
            --end;
        return value.substr(start, end - start);
    }

    bool LooksLikeBase64Char(char c)
    {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=';
    }

    bool LooksLikeBase64Blob(const std::string& value)
    {
        if (value.size() < 24 || value.size() % 4 != 0)
            return false;
        for (char c : value)
        {
            if (!LooksLikeBase64Char(c))
                return false;
        }
        return true;
    }

    // a lightweight decoder is enough here because we only need analyst previews.
    std::string DecodeBase64(const std::string& input)
    {
        static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        int val = 0;
        int valb = -8;
        for (unsigned char c : input)
        {
            if (std::isspace(c))
                continue;
            if (c == '=')
                break;
            const std::size_t pos = alphabet.find(static_cast<char>(c));
            if (pos == std::string::npos)
                return "";
            val = (val << 6) + static_cast<int>(pos);
            valb += 6;
            if (valb >= 0)
            {
                out.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

    bool LooksLikeMostlyPrintable(const std::string& value)
    {
        if (value.empty())
            return false;
        std::size_t printable = 0;
        for (unsigned char c : value)
        {
            if ((c >= 32 && c <= 126) || c == '\r' || c == '\n' || c == '\t')
                ++printable;
        }
        return printable >= (value.size() * 7) / 10;
    }
}

// collects obfuscation signals that can explain otherwise sparse or indirect artifacts.
DeobfuscationResult AnalyzeDeobfuscation(const std::string& searchableText, const Indicators& indicators)
{
    DeobfuscationResult result;

    if (searchableText.find("`") != std::string::npos && searchableText.find("powershell") != std::string::npos)
    {
        AddUnique(result.findings, "PowerShell backtick escaping suggests command obfuscation");
        result.scoreBoost += 3;
    }
    if (searchableText.find("^") != std::string::npos && searchableText.find("cmd") != std::string::npos)
    {
        AddUnique(result.findings, "Command-line caret escaping suggests shell obfuscation");
        result.scoreBoost += 2;
    }
    if (searchableText.find("FromBase64String") != std::string::npos || searchableText.find("base64") != std::string::npos)
    {
        AddUnique(result.findings, "Embedded base64 decode workflow detected");
        result.scoreBoost += 2;
    }

    // only keep decoded text that is printable enough to help triage.
    for (const auto& blob : indicators.base64Blobs)
    {
        const std::string candidate = Trim(blob);
        if (!LooksLikeBase64Blob(candidate))
            continue;
        const std::string decoded = DecodeBase64(candidate);
        if (decoded.empty() || !LooksLikeMostlyPrintable(decoded))
            continue;

        std::string preview = decoded.substr(0, std::min<std::size_t>(decoded.size(), 120));
        for (char& c : preview)
        {
            if (c == '\r' || c == '\n')
                c = ' ';
        }
        AddUnique(result.decodedArtifacts, preview);
        AddUnique(result.findings, "Decoded printable base64 content during static deobfuscation");
        result.scoreBoost += 4;
    }

    return result;
}
