#include "analyzers/indicator_extractor.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>
// string harvesting pipeline that normalizes and categorizes extracted artifacts.

// text cleanup, artifact classification, and noise filters shared by both extraction entry points.
namespace
{
    constexpr std::size_t kMinStringLength = 6;
    constexpr std::size_t kChunkSize = 1024 * 1024;
    constexpr std::size_t kCarryLimit = 512;
    constexpr std::size_t kMaxItemsPerCategory = 12;
    constexpr std::size_t kMinWideStringLength = 6;

    std::string ToLowerCopy(const std::string& input)
    {
        std::string out = input;
        std::transform(out.begin(), out.end(), out.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    // trim trailing counters and punctuation so nearly identical artifacts collapse together.
    std::string NormalizeForCompare(const std::string& input)
    {
        std::string out = ToLowerCopy(input);
        while (!out.empty() && (std::isdigit(static_cast<unsigned char>(out.back())) || out.back() == '\0'))
            out.pop_back();
        while (!out.empty() && std::ispunct(static_cast<unsigned char>(out.back())) && out.back() != '/' && out.back() != '.')
            out.pop_back();
        return out;
    }

    void AddUnique(std::vector<std::string>& target, const std::string& value, std::size_t maxItems = kMaxItemsPerCategory)
    {
        if (value.empty() || target.size() >= maxItems)
            return;
        // normalize before deduping so path or url variants do not flood the report.
        const std::string normalized = NormalizeForCompare(value);
        for (const auto& existing : target)
        {
            if (NormalizeForCompare(existing) == normalized)
                return;
        }
        target.push_back(value);
    }

    bool IsPrintableAscii(unsigned char c)
    {
        return c >= 32 && c <= 126;
    }

    bool LooksLikeIp(const std::string& s)
    {
        int dots = 0;
        for (char c : s)
        {
            if (c == '.')
                ++dots;
            else if (!std::isdigit(static_cast<unsigned char>(c)))
                return false;
        }
        return dots == 3;
    }

    bool LooksLikeEmail(const std::string& s)
    {
        const std::size_t at = s.find('@');
        const std::size_t dot = s.rfind('.');
        return at != std::string::npos && dot != std::string::npos && dot > at + 1;
    }

    bool LooksLikeUrl(const std::string& s)
    {
        return s.find("http://") != std::string::npos || s.find("https://") != std::string::npos;
    }

    bool LooksLikeRegistry(const std::string& s)
    {
        const std::string lower = ToLowerCopy(s);
        return lower.find("hklm\\") != std::string::npos ||
            lower.find("hkcu\\") != std::string::npos ||
            lower.find("hkcr\\") != std::string::npos ||
            lower.find("hkey_local_machine\\") != std::string::npos ||
            lower.find("hkey_current_user\\") != std::string::npos;
    }

    bool LooksLikePath(const std::string& s)
    {
        return s.size() >= 3 &&
            std::isalpha(static_cast<unsigned char>(s[0])) &&
            s[1] == ':' &&
            (s[2] == '\\' || s[2] == '/');
    }

    bool LooksLikeBase64(const std::string& s)
    {
        if (s.size() < 40)
            return false;
        for (char c : s)
        {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '='))
                return false;
        }
        return true;
    }

    std::string ExtractDomainFromUrl(const std::string& url)
    {
        std::string tmp = url;
        const std::size_t schemePos = tmp.find("://");
        if (schemePos != std::string::npos)
            tmp = tmp.substr(schemePos + 3);
        const std::size_t slashPos = tmp.find('/');
        if (slashPos != std::string::npos)
            tmp = tmp.substr(0, slashPos);
        const std::size_t queryPos = tmp.find('?');
        if (queryPos != std::string::npos)
            tmp = tmp.substr(0, queryPos);
        const std::size_t portPos = tmp.find(':');
        if (portPos != std::string::npos)
            tmp = tmp.substr(0, portPos);
        return tmp;
    }

    // salvage the useful url or path portion from noisy printable runs.
    std::string CleanArtifactString(const std::string& value)
    {
        std::string out;
        out.reserve(value.size());
        bool seenHttp = false;
        for (std::size_t i = 0; i < value.size(); ++i)
        {
            if (!seenHttp)
            {
                if ((i + 7 <= value.size() && value.compare(i, 7, "http://") == 0) ||
                    (i + 8 <= value.size() && value.compare(i, 8, "https://") == 0) ||
                    (i + 4 <= value.size() && value.compare(i, 4, "www.") == 0))
                {
                    seenHttp = true;
                    out.assign(value.begin() + static_cast<long long>(i), value.end());
                    break;
                }
            }
        }
        if (!seenHttp)
            out = value;

        std::string cleaned;
        cleaned.reserve(out.size());
        for (char c : out)
        {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc < 32 || uc > 126)
                break;
            if (std::isalnum(uc) || c == '/' || c == '.' || c == '-' || c == '_' || c == ':' || c == '?' || c == '&' || c == '=' || c == '%' || c == '#')
                cleaned.push_back(c);
            else
                break;
        }

        while (!cleaned.empty() && (std::isdigit(static_cast<unsigned char>(cleaned.back())) || cleaned.back() == '#'))
            cleaned.pop_back();
        while (!cleaned.empty() && std::ispunct(static_cast<unsigned char>(cleaned.back())) && cleaned.back() != '/' && cleaned.back() != '.')
            cleaned.pop_back();
        return cleaned;
    }

    bool IsNoiseUrl(const std::string& lower)
    {
        // common repo and docs links are filtered because bundled libraries often carry them.
        static const std::vector<std::string> noiseTokens = {
            "github.com/", "raw.githubusercontent.com/", "gitlab.com/", "nuget.org/", "learn.microsoft.com/",
            "docs.microsoft.com/", "project.org/", "apache.org/", "readthedocs", "wikipedia.org/",
            "/readme", "/license", ".md", ".git", "src/", "master/", "blob/", "tree/"
        };
        for (const auto& token : noiseTokens)
        {
            if (lower.find(token) != std::string::npos)
                return true;
        }
        return false;
    }

    bool IsTrustReferenceUrl(const std::string& lower)
    {
        // keep certificate plumbing separate from actual network iocs.
        static const std::vector<std::string> trustTokens = {
            "crl.microsoft.com", "microsoft.com/pki", "/crl/", "/certs/", ".crt", ".crl",
            "ocsp.", "digicert.com", "globalsign.com", "verisign.com", "sectigo.com",
            "comodoca.com", "letsencrypt.org", "entrust.net"
        };
        for (const auto& token : trustTokens)
        {
            if (lower.find(token) != std::string::npos)
                return true;
        }
        return false;
    }

    bool IsKnownLibraryNoise(const std::string& lower, std::string& libraryLabel)
    {
        // library fingerprints are preserved as context, but they should not score like malware artifacts.
        static const std::vector<std::pair<std::string, std::string>> knownLibraries = {
            {"nlog", "NLog"},
            {"noesis", "Noesis"},
            {"noesisgui", "NoesisGUI"},
            {"log4net", "log4net"},
            {"spdlog", "spdlog"},
            {"boost::", "Boost"},
            {"qt", "Qt"},
            {"unity", "Unity"},
            {"unreal", "Unreal Engine"},
            {"openssl", "OpenSSL"},
            {"curl", "libcurl"},
            {"zstd", "Zstandard"},
            {"rapidjson", "RapidJSON"},
            {"protobuf", "Protocol Buffers"}
        };
        for (const auto& item : knownLibraries)
        {
            if (lower.find(item.first) != std::string::npos)
            {
                libraryLabel = item.second;
                return true;
            }
        }
        return false;
    }

    void AddRule(Indicators& indicators, const std::string& rule)
    {
        AddUnique(indicators.matchedRules, rule, 16);
    }

    void AddBehaviorHighlight(Indicators& indicators, const std::string& highlight)
    {
        AddUnique(indicators.behaviorHighlights, highlight, 8);
    }

    void AddAnalysisContextReference(Indicators& indicators, const std::string& reference)
    {
        AddUnique(indicators.analysisToolReferences, reference, 10);
        indicators.hasSecurityAnalysisContext = true;
    }

    void RegisterEvidence(unsigned int& counter)
    {
        if (counter < 255)
            ++counter;
    }

    bool IsAnalysisToolReference(const std::string& lower, std::string& reference)
    {
        static const std::vector<std::pair<std::string, std::string>> tokens = {
            {"binarylens", "BinaryLens project context detected"},
            {"virustotal", "VirusTotal analysis reference detected"},
            {"analyst view", "Analyst workflow text detected"},
            {"ioc export", "IOC export workflow text detected"},
            {"scan result", "Embedded scan-result/report phrasing detected"},
            {"threat categories", "Threat categorization/report text detected"},
            {"heuristic-based", "Heuristic analysis disclaimer text detected"},
            {"sandbox", "Sandbox / analysis environment reference detected"},
            {"yara", "YARA or rule-based analysis reference detected"},
            {"authenticode", "Authenticode validation reference detected"},
            {"reverse engineer", "Reverse engineering reference detected"},
            {"malware analysis", "Malware analysis terminology detected"},
            {"threat intel", "Threat intelligence terminology detected"}
        };
        for (const auto& item : tokens)
        {
            if (lower.find(item.first) != std::string::npos)
            {
                reference = item.second;
                return true;
            }
        }
        return false;
    }

    bool ContainsAny(const std::string& lower, const std::vector<std::string>& patterns)
    {
        for (const auto& pattern : patterns)
        {
            if (lower.find(pattern) != std::string::npos)
                return true;
        }
        return false;
    }

    // classifies each recovered token into urls, ips, registry paths, analysis context, and behavior cues.
void ProcessString(const std::string& s, Indicators& indicators, bool unicodeSource = false)
    {
        if (s.size() < kMinStringLength || s.size() > 512)
            return;

        if (unicodeSource)
            ++indicators.unicodeStringCount;
        else
            ++indicators.asciiStringCount;

        const std::string lower = ToLowerCopy(s);

        // analysis-tool references can explain suspicious-looking strings in self-scans.
        std::string analysisReference;
        if (IsAnalysisToolReference(lower, analysisReference))
            AddAnalysisContextReference(indicators, analysisReference);

        std::string libraryLabel;
        if (IsKnownLibraryNoise(lower, libraryLabel))
        {
            AddUnique(indicators.embeddedLibraries, libraryLabel, 10);
            ++indicators.filteredNoiseCount;
            return;
        }

        // url hits pass through noise and trust filters before joining the main buckets.
        if (LooksLikeUrl(s))
        {
            const std::string cleanedUrl = CleanArtifactString(s);
            const std::string cleanedLower = ToLowerCopy(cleanedUrl);
            if (IsNoiseUrl(cleanedLower))
            {
                ++indicators.filteredNoiseCount;
            }
            else if (IsTrustReferenceUrl(cleanedLower))
            {
                AddUnique(indicators.trustReferences, cleanedUrl, 6);
                ++indicators.filteredNoiseCount;
            }
            else
            {
                AddUnique(indicators.urls, cleanedUrl, 8);
                const std::string domain = ExtractDomainFromUrl(cleanedUrl);
                if (!domain.empty())
                    AddUnique(indicators.domains, domain, 8);
            }
        }

        if (LooksLikeIp(s))
            AddUnique(indicators.ips, NormalizeForCompare(s), 8);
        if (LooksLikeEmail(s))
            AddUnique(indicators.emails, s, 8);
        if (LooksLikePath(s))
            AddUnique(indicators.filePaths, s, 8);
        if (LooksLikeRegistry(s))
            AddUnique(indicators.registryKeys, s, 8);
        if (LooksLikeBase64(s))
            AddUnique(indicators.base64Blobs, "High-entropy Base64-like blob", 4);

        // keep the command list broad, but only store the matched token instead of the whole string.
        static const std::vector<std::string> suspiciousCommandTokens = {
            "powershell", "cmd.exe", "wscript", "cscript", "rundll32", "regsvr32", "mshta",
            "bitsadmin", "certutil", "wmic", "vssadmin", "bcdedit", "schtasks", "fodhelper",
            "net user", "net localgroup", "downloadstring", "frombase64string",
            "invoke-expression", "-enc", "-encodedcommand", "curl ", "wget ",
            "rclone", "wevtutil", "procdump", "esentutl", "7z a", "attrib +h"
        };
        for (const auto& token : suspiciousCommandTokens)
        {
            if (lower.find(token) != std::string::npos)
                AddUnique(indicators.suspiciousCommands, token, 8);
        }

        // evidence counters let later scoring scale with repeated support instead of one stray token.
        const bool strongPersistence = ContainsAny(lower, { "currentversion\\run", "runonce", "startup\\", "startupapproved", "schtasks /create", "createtask", "new-service", "createservice", "sc create", "winlogon\\shell", "userinit" });
        if (strongPersistence)
        {
            indicators.hasPersistenceTraits = true;
            RegisterEvidence(indicators.persistenceEvidenceCount);
            AddRule(indicators, "Persistence-related artifact found");
            AddBehaviorHighlight(indicators, "Persistence behavior detected");
        }

        if (ContainsAny(lower, { "setup bootstrapper", "vs_setup", "visual studio setup", "burn engine", "wix bundle", "installcleanup", "install bundle", "bootstrap application" }))
            indicators.hasInstallerTraits = true;
        if (ContainsAny(lower, { "writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc", "virtualallocex", "process hollow", "reflective loader", "shellcode" }))
        {
            indicators.hasInjectionTraits = true;
            RegisterEvidence(indicators.injectionEvidenceCount);
            AddRule(indicators, "Process injection / loader artifact found");
            AddBehaviorHighlight(indicators, "Process injection or loader behavior detected");
        }

        if (ContainsAny(lower, { "isdebuggerpresent", "checkremotedebuggerpresent", "beingdebugged", "vmware", "virtualbox", "sandbox", "wireshark", "procmon", "ollydbg", "x64dbg" }))
        {
            indicators.hasEvasionTraits = true;
            RegisterEvidence(indicators.evasionEvidenceCount);
            AddRule(indicators, "Anti-analysis / evasion artifact found");
            AddBehaviorHighlight(indicators, "Anti-analysis or evasion behavior detected");
        }

        if (ContainsAny(lower, { "urldownloadtofile", "invoke-webrequest", "downloadstring", "bitsadmin", "certutil -urlcache", "winhttp", "internetopen", "httpopenrequest", "pastebin", "discordapp", "cdn.discordapp", "telegram", "api.ipify.org", "checkip.amazonaws.com" }))
        {
            indicators.hasDownloaderTraits = true;
            RegisterEvidence(indicators.downloaderEvidenceCount);
            AddRule(indicators, "Downloader / payload retrieval artifact found");
            AddBehaviorHighlight(indicators, "Downloader or payload retrieval behavior detected");
        }

        if (ContainsAny(lower, { "vssadmin delete shadows", "wmic shadowcopy delete", "wbadmin delete catalog", "bcdedit /set {default} recoveryenabled no", "bootstatuspolicy ignoreallfailures", "ransom note", "recover your files" }))
        {
            indicators.hasRansomwareTraits = true;
            RegisterEvidence(indicators.ransomwareEvidenceCount);
            AddRule(indicators, "Ransomware-related artifact found");
            AddBehaviorHighlight(indicators, "Ransomware-related destructive behavior detected");
        }

        if (ContainsAny(lower, { "getasynckeystate", "setwindowshookex", "lowlevelkeyboardproc", "keyboard hook", "keylogger", "keystroke" }))
        {
            indicators.hasKeyloggingTraits = true;
            indicators.hasSpywareTraits = true;
            RegisterEvidence(indicators.keyloggingEvidenceCount);
            RegisterEvidence(indicators.spywareEvidenceCount);
            AddRule(indicators, "Keylogging-related artifact found");
            AddBehaviorHighlight(indicators, "Keylogging or surveillance behavior detected");
        }

        if (ContainsAny(lower, { "screenshot", "screen capture", "clipboard", "webcam", "microphone" }))
        {
            indicators.hasSpywareTraits = true;
            RegisterEvidence(indicators.spywareEvidenceCount);
            AddRule(indicators, "Spyware / surveillance artifact found");
            AddBehaviorHighlight(indicators, "Spyware or surveillance behavior detected");
        }

        if (ContainsAny(lower, { "mimikatz", "sekurlsa", "lsass", "vaultcmd", "credman", "cryptunprotectdata", "browser\\login data", "cookies.sqlite", "wallet.dat" }))
        {
            indicators.hasCredentialTheftTraits = true;
            AddRule(indicators, "Credential / secret theft artifact found");
            AddBehaviorHighlight(indicators, "Credential or secret theft behavior detected");
        }
    }

    void ProcessWideStringBuffer(const std::string& s, Indicators& indicators)
    {
        if (s.size() < kMinWideStringLength)
            return;

        ProcessString(s, indicators, true);
    }

    // tokenizes the aggregated text stream and feeds each candidate through the indicator rules.
void ScanTextBuffer(const std::string& input, Indicators& indicators)
    {
        std::string current;
        std::string currentWide;
        current.reserve(512);
        currentWide.reserve(512);
        for (std::size_t i = 0; i < input.size(); ++i)
        {
            const unsigned char c = static_cast<unsigned char>(input[i]);
            if (IsPrintableAscii(c))
            {
                current.push_back(static_cast<char>(c));
                if (current.size() > 4096)
                {
                    ProcessString(current, indicators, false);
                    current.clear();
                }
            }
            else
            {
                ProcessString(current, indicators, false);
                current.clear();
            }

            // look for utf-16le strings in parallel with the ascii pass.
            if ((i + 1) < input.size())
            {
                const unsigned char c2 = static_cast<unsigned char>(input[i + 1]);
                if (IsPrintableAscii(c) && c2 == 0)
                {
                    currentWide.push_back(static_cast<char>(c));
                    ++i;
                    if (currentWide.size() > 4096)
                    {
                        ProcessWideStringBuffer(currentWide, indicators);
                        currentWide.clear();
                    }
                }
                else if (!currentWide.empty())
                {
                    ProcessWideStringBuffer(currentWide, indicators);
                    currentWide.clear();
                }
            }
        }

        ProcessString(current, indicators, false);
        ProcessWideStringBuffer(currentWide, indicators);
    }

}

// reads bytes from disk, recovers ascii and wide strings, then builds the final indicator set.
Indicators ExtractIndicators(const std::string& filePath)
{
    Indicators indicators;

    try
    {
        std::ifstream file(filePath, std::ios::binary);
        if (!file)
            return indicators;

        std::vector<char> chunk(kChunkSize);
        std::string carry;
        std::string wideCarry;
        carry.reserve(kCarryLimit);
        wideCarry.reserve(kCarryLimit);

        while (file)
        {
            file.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
            const std::streamsize bytesRead = file.gcount();
            if (bytesRead <= 0)
                break;

            std::string current = carry;
            std::string currentWide = wideCarry;
            for (std::streamsize i = 0; i < bytesRead; ++i)
            {
                const unsigned char c = static_cast<unsigned char>(chunk[static_cast<std::size_t>(i)]);
                if (IsPrintableAscii(c))
                {
                    current.push_back(static_cast<char>(c));
                    if (current.size() > 4096)
                    {
                        ProcessString(current, indicators, false);
                        current.clear();
                    }
                }
                else
                {
                    ProcessString(current, indicators, false);
                    current.clear();
                }

                if ((i + 1) < bytesRead)
                {
                    const unsigned char c2 = static_cast<unsigned char>(chunk[static_cast<std::size_t>(i + 1)]);
                    if (IsPrintableAscii(c) && c2 == 0)
                    {
                        currentWide.push_back(static_cast<char>(c));
                        ++i;
                        if (currentWide.size() > 4096)
                        {
                            ProcessWideStringBuffer(currentWide, indicators);
                            currentWide.clear();
                        }
                    }
                    else if (!currentWide.empty())
                    {
                        ProcessWideStringBuffer(currentWide, indicators);
                        currentWide.clear();
                    }
                }
                else if (!currentWide.empty() && !IsPrintableAscii(c))
                {
                    ProcessWideStringBuffer(currentWide, indicators);
                    currentWide.clear();
                }
            }

            // keep a short tail so split strings can continue across chunk boundaries.
            carry = current;
            if (carry.size() > kCarryLimit)
                carry = carry.substr(carry.size() - kCarryLimit);
            wideCarry = currentWide;
            if (wideCarry.size() > kCarryLimit)
                wideCarry = wideCarry.substr(wideCarry.size() - kCarryLimit);
        }

        ProcessString(carry, indicators, false);
        ProcessWideStringBuffer(wideCarry, indicators);
    }
    catch (...)
    {
        return Indicators{};
    }

    return indicators;
}


// reuses the same categorization rules when upstream stages already provide searchable text.
Indicators ExtractIndicatorsFromText(const std::string& searchableText)
{
    Indicators indicators;
    try
    {
        ScanTextBuffer(searchableText, indicators);
    }
    catch (...)
    {
        return Indicators{};
    }
    return indicators;
}
