#include "core/deobfuscation_engine.h"
#include "common/string_utils.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <string>

// encoded-string and obfuscation heuristics used to recover stronger indicators.

namespace
{
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

    bool LooksInterestingDecodedText(const std::string& value)
    {
        const std::string lower = bl::common::ToLowerCopy(value);
        return lower.find("http") != std::string::npos ||
               lower.find("powershell") != std::string::npos ||
               lower.find("cmd") != std::string::npos ||
               lower.find("mz") != std::string::npos ||
               lower.find("loadlibrary") != std::string::npos ||
               lower.find("virtualalloc") != std::string::npos;
    }

    std::string BuildPreview(const std::string& value)
    {
        std::string preview = value.substr(0, std::min<std::size_t>(value.size(), 120));
        for (char& c : preview)
        {
            if (c == '\r' || c == '\n')
                c = ' ';
        }
        return preview;
    }

    bool LooksLikeHexBlob(const std::string& value)
    {
        if (value.size() < 16 || value.size() % 2 != 0)
            return false;
        for (char c : value)
        {
            if (!std::isxdigit(static_cast<unsigned char>(c)))
                return false;
        }
        return true;
    }

    int HexNibbleValue(char c)
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    }

    std::string DecodeHexBlob(const std::string& value)
    {
        if (!LooksLikeHexBlob(value))
            return "";
        std::string out;
        out.reserve(value.size() / 2);
        for (std::size_t i = 0; i + 1 < value.size(); i += 2)
        {
            const int high = HexNibbleValue(value[i]);
            const int low = HexNibbleValue(value[i + 1]);
            if (high < 0 || low < 0)
                return "";
            out.push_back(static_cast<char>((high << 4) | low));
        }
        return out;
    }

    std::string DecodeEscapedHexBlob(const std::string& value)
    {
        std::string compact;
        compact.reserve(value.size());
        for (std::size_t i = 0; i < value.size(); ++i)
        {
            if (i + 3 < value.size() && value[i] == '\\' && (value[i + 1] == 'x' || value[i + 1] == 'X') &&
                std::isxdigit(static_cast<unsigned char>(value[i + 2])) && std::isxdigit(static_cast<unsigned char>(value[i + 3])))
            {
                compact.push_back(value[i + 2]);
                compact.push_back(value[i + 3]);
                i += 3;
            }
        }
        return DecodeHexBlob(compact);
    }

    std::string Rot13Copy(const std::string& value)
    {
        std::string out = value;
        for (char& c : out)
        {
            if (c >= 'a' && c <= 'z')
                c = static_cast<char>('a' + ((c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z')
                c = static_cast<char>('A' + ((c - 'A' + 13) % 26));
        }
        return out;
    }

    std::string TrySingleByteXorDecode(const std::string& value, unsigned int& discoveredKey)
    {
        if (value.size() < 12)
            return "";

        for (unsigned int key = 1; key <= 0xFF; ++key)
        {
            std::string decoded;
            decoded.reserve(value.size());
            std::size_t printable = 0;
            for (unsigned char c : value)
            {
                const unsigned char candidate = static_cast<unsigned char>(c ^ key);
                decoded.push_back(static_cast<char>(candidate));
                if ((candidate >= 32 && candidate <= 126) || candidate == '\r' || candidate == '\n' || candidate == '\t')
                    ++printable;
            }

            if (printable < (decoded.size() * 8) / 10)
                continue;
            if (!LooksInterestingDecodedText(decoded) && !LooksLikeMostlyPrintable(decoded))
                continue;

            discoveredKey = key;
            return decoded;
        }

        return "";
    }
}

// collects obfuscation signals that can explain otherwise sparse or indirect artifacts.
DeobfuscationResult AnalyzeDeobfuscation(const std::string& searchableText, const Indicators& indicators)
{
    DeobfuscationResult result;

    const std::string lowerSearchableText = bl::common::ToLowerCopy(searchableText);
    if (searchableText.find("`") != std::string::npos && lowerSearchableText.find("powershell") != std::string::npos)
    {
        bl::common::AddUnique(result.findings, "PowerShell backtick escaping suggests command obfuscation", 10);
        result.scoreBoost += 3;
    }
    if (searchableText.find("^") != std::string::npos && lowerSearchableText.find("cmd") != std::string::npos)
    {
        bl::common::AddUnique(result.findings, "Command-line caret escaping suggests shell obfuscation", 10);
        result.scoreBoost += 2;
    }
    if (lowerSearchableText.find("frombase64string") != std::string::npos || lowerSearchableText.find("base64") != std::string::npos)
    {
        bl::common::AddUnique(result.findings, "Embedded base64 decode workflow detected", 10);
        result.scoreBoost += 2;
    }
    if (lowerSearchableText.find("charcode") != std::string::npos || lowerSearchableText.find("fromcharcode") != std::string::npos)
    {
        bl::common::AddUnique(result.findings, "Character-code string rebuilding pattern detected", 10);
        result.scoreBoost += 2;
    }

    for (const auto& blob : indicators.base64Blobs)
    {
        const std::string candidate = bl::common::TrimCopy(blob);
        if (!LooksLikeBase64Blob(candidate))
            continue;
        const std::string decoded = DecodeBase64(candidate);
        if (decoded.empty() || !LooksLikeMostlyPrintable(decoded))
            continue;

        bl::common::AddUnique(result.decodedArtifacts, BuildPreview(decoded), 8);
        bl::common::AddUnique(result.findings, "Decoded printable base64 content during static deobfuscation", 10);
        result.scoreBoost += 4;
    }

    std::vector<std::string> candidateStrings = indicators.base64Blobs;
    candidateStrings.insert(candidateStrings.end(), indicators.suspiciousCommands.begin(), indicators.suspiciousCommands.end());
    candidateStrings.insert(candidateStrings.end(), indicators.urls.begin(), indicators.urls.end());
    candidateStrings.insert(candidateStrings.end(), indicators.domains.begin(), indicators.domains.end());
    candidateStrings.insert(candidateStrings.end(), indicators.behaviorHighlights.begin(), indicators.behaviorHighlights.end());

    for (const auto& rawCandidate : candidateStrings)
    {
        const std::string candidate = bl::common::TrimCopy(rawCandidate);
        if (candidate.empty())
            continue;

        const std::string hexDecoded = DecodeHexBlob(candidate);
        if (!hexDecoded.empty() && LooksLikeMostlyPrintable(hexDecoded))
        {
            bl::common::AddUnique(result.decodedArtifacts, BuildPreview(hexDecoded), 8);
            bl::common::AddUnique(result.findings, "Recovered printable text from contiguous hex-encoded content", 10);
            result.scoreBoost += 3;
        }

        const std::string escapedHexDecoded = DecodeEscapedHexBlob(candidate);
        if (!escapedHexDecoded.empty() && LooksLikeMostlyPrintable(escapedHexDecoded))
        {
            bl::common::AddUnique(result.decodedArtifacts, BuildPreview(escapedHexDecoded), 8);
            bl::common::AddUnique(result.findings, "Recovered printable text from escaped hex content", 10);
            result.scoreBoost += 3;
        }

        if (candidate.size() >= 16)
        {
            const std::string rot13 = Rot13Copy(candidate);
            if (rot13 != candidate && LooksLikeMostlyPrintable(rot13) && LooksInterestingDecodedText(rot13))
            {
                bl::common::AddUnique(result.decodedArtifacts, BuildPreview(rot13), 8);
                bl::common::AddUnique(result.findings, "ROT13-style reversible text obfuscation detected", 10);
                result.scoreBoost += 2;
            }
        }

        unsigned int key = 0;
        const std::string xorDecoded = TrySingleByteXorDecode(candidate, key);
        if (!xorDecoded.empty())
        {
            bl::common::AddUnique(result.decodedArtifacts, BuildPreview(xorDecoded), 8);
            bl::common::AddUnique(result.findings, "Single-byte xor decoding recovered printable content (key 0x" +
                                                   std::string(key < 16 ? "0" : "") +
                                                   [&]() { char buf[8] = {}; std::snprintf(buf, sizeof(buf), "%X", key); return std::string(buf); }() + ")", 10);
            result.scoreBoost += 4;
        }
    }

    return result;
}
