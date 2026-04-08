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
    // these helpers prefer cheap textual recovery over heavyweight decoding because the goal is analyst context.
    bool LooksLikeBase64Char(char c)
    // answers this looks like base64 char check in one place so the surrounding logic stays readable.
    {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=';
    }

    // base64 checks are intentionally strict enough to skip most ordinary prose and small tokens.
    bool LooksLikeBase64Blob(const std::string& value)
    // answers this looks like base64 blob check in one place so the surrounding logic stays readable.
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
    // keeps the decode base64 step local to this deobfuscation flow file so callers can stay focused on intent.
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

    // printable gating keeps recovered artifacts readable in the report instead of dumping raw noise.
    bool LooksLikeMostlyPrintable(const std::string& value)
    // answers this looks like mostly printable check in one place so the surrounding logic stays readable.
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

    // this is not a verdict gate; it only decides whether a recovered preview is worth surfacing.
    bool LooksInterestingDecodedText(const std::string& value)
    // answers this looks interesting decoded text check in one place so the surrounding logic stays readable.
    {
        const std::string lower = bl::common::ToLowerCopy(value);
        return lower.find("http") != std::string::npos ||
               lower.find("powershell") != std::string::npos ||
               lower.find("cmd") != std::string::npos ||
               lower.find("mz") != std::string::npos ||
               lower.find("loadlibrary") != std::string::npos ||
               lower.find("virtualalloc") != std::string::npos;
    }

    // previews are trimmed early so one decoded blob cannot dominate the whole section.
    std::string BuildPreview(const std::string& value)
    // builds this deobfuscation flow fragment in one place so the surrounding code can stay focused on flow.
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
    // answers this looks like hex blob check in one place so the surrounding logic stays readable.
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
    // keeps the hex nibble value step local to this deobfuscation flow file so callers can stay focused on intent.
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    }

    // contiguous hex shows up often enough in staged scripts to justify a dedicated pass.
    std::string DecodeHexBlob(const std::string& value)
    // keeps the decode hex blob step local to this deobfuscation flow file so callers can stay focused on intent.
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

    // escaped hex is common in script obfuscation, so collapse it before reuse of the plain hex path.
    std::string DecodeEscapedHexBlob(const std::string& value)
    // keeps the decode escaped hex blob step local to this deobfuscation flow file so callers can stay focused on intent.
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

    // rot13 is low-cost to check and sometimes reveals text hidden in otherwise ordinary-looking strings.
    std::string Rot13Copy(const std::string& value)
    // keeps the rot13 copy step local to this deobfuscation flow file so callers can stay focused on intent.
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

    // the xor pass stays conservative by requiring high printability before surfacing recovered text.
    std::string TrySingleByteXorDecode(const std::string& value, unsigned int& discoveredKey)
    // keeps the try single byte xor decode step local to this deobfuscation flow file so callers can stay focused on intent.
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
// collects obfuscation signals that can explain otherwise sparse or indirect artifacts.
DeobfuscationResult AnalyzeDeobfuscation(const std::string& searchableText, const Indicators& indicators)
// runs the analyze deobfuscation pass and returns a focused result for the broader deobfuscation flow pipeline.
{
    DeobfuscationResult result;

    // broad text cues are checked first because they often explain later recovered fragments.
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

    // explicit base64 blobs are the cleanest decode candidates, so they get their own pass first.
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

    // the second pass broadens coverage to other extracted strings that may hide smaller transforms.
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
