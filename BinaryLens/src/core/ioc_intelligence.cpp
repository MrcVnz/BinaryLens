#include "core/ioc_intelligence.h"

#include <algorithm>
#include <cctype>
// ioc enrichment and summarization built from extracted communication artifacts.

// ioc shaping helpers that normalize and rank extracted communication artifacts.
namespace
{
    std::string ToLowerCopy(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    void AddSummary(std::vector<std::string>& out, const std::string& value)
    {
        if (value.empty())
            return;
        if (std::find(out.begin(), out.end(), value) == out.end())
            out.push_back(value);
    }

    void AddFinding(IocIntelligenceResult& result, const std::string& artifact, const std::string& classification, const std::string& rationale)
    {
        if (artifact.empty())
            return;
        if (result.findings.size() < 12)
            result.findings.push_back({artifact, classification, rationale});
        AddSummary(result.summary, artifact + " -> " + classification);
    }
}

// summarizes the strongest network and system artifacts into actionable intelligence buckets.
IocIntelligenceResult AnalyzeIocIntelligence(const Indicators& indicators)
{
    IocIntelligenceResult result;

    // urls are usually the richest iocs, so classify them first.
    for (const auto& url : indicators.urls)
    {
        const std::string lower = ToLowerCopy(url);
        if (lower.find("aka.ms") != std::string::npos || lower.find("microsoft.com") != std::string::npos || lower.find("google.com") != std::string::npos)
            AddFinding(result, url, "Trusted infrastructure", "Matches a common vendor or CDN domain");
        else if (lower.find("raw") != std::string::npos || lower.find("paste") != std::string::npos || lower.find("discord") != std::string::npos)
            AddFinding(result, url, "Delivery-oriented infrastructure", "Textual pattern resembles payload hosting or direct content delivery");
        else
            AddFinding(result, url, "Unclassified network artifact", "No clear allow-list or high-risk pattern matched");
    }

    for (const auto& domain : indicators.domains)
    {
        const std::string lower = ToLowerCopy(domain);
        if (lower.find("microsoft") != std::string::npos || lower.find("google") != std::string::npos || lower.find("github") != std::string::npos)
            AddFinding(result, domain, "Known service domain", "Domain name resembles a widely used legitimate platform");
        else if (std::count(lower.begin(), lower.end(), '.') == 0)
            AddFinding(result, domain, "Incomplete domain artifact", "Extracted token may be truncated and needs analyst review");
        else
            AddFinding(result, domain, "Unknown domain", "No contextual allow-list matched");
    }

    // raw ips get a simple local-vs-external split for fast triage.
    for (const auto& ip : indicators.ips)
    {
        const bool privateRange = ip.rfind("10.", 0) == 0 || ip.rfind("192.168.", 0) == 0 || ip.rfind("172.16.", 0) == 0 || ip.rfind("172.17.", 0) == 0 || ip.rfind("127.", 0) == 0;
        if (privateRange)
            AddFinding(result, ip, "Private or local address", "The IP points to a non-routable or loopback range");
        else
            AddFinding(result, ip, "Raw external IP", "Hard-coded public IPs can indicate direct infrastructure usage");
    }

    for (const auto& command : indicators.suspiciousCommands)
    {
        const std::string lower = ToLowerCopy(command);
        if (lower.find("powershell") != std::string::npos || lower.find("cmd.exe") != std::string::npos)
            AddFinding(result, command, "Execution utility", "Command references a common script or shell launcher");
        else if (lower.find("schtasks") != std::string::npos || lower.find("reg add") != std::string::npos)
            AddFinding(result, command, "Persistence-related artifact", "Command matches a common persistence workflow");
    }

    return result;
}
