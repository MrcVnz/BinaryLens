#include "core/ioc_intelligence.h"
#include "common/string_utils.h"

#include <algorithm>

// ioc enrichment and summarization built from extracted communication artifacts.

namespace
{
    // summaries stay short so the report can surface the strongest artifacts without flooding the reader.
    void AddSummary(std::vector<std::string>& out, const std::string& value)
    // adds this detail through one gate so duplicate or noisy output stays under control.
    {
        bl::common::AddUnique(out, value, 12);
    }

    // every finding stores both a bucket and a rationale so the ioc section reads as analysis, not a dump.
    void AddFinding(IocIntelligenceResult& result, const std::string& artifact, const std::string& classification, const std::string& rationale)
    // adds this detail through one gate so duplicate or noisy output stays under control.
    {
        if (artifact.empty())
            return;
        if (result.findings.size() < 12)
            result.findings.push_back({artifact, classification, rationale});
        AddSummary(result.summary, artifact + " -> " + classification);
    }
}

// summarizes the strongest network and system artifacts into actionable intelligence buckets.
// summarizes the strongest network and system artifacts into actionable intelligence buckets.
IocIntelligenceResult AnalyzeIocIntelligence(const Indicators& indicators)
// runs the analyze ioc intelligence pass and returns a focused result for the broader ioc enrichment pipeline.
{
    IocIntelligenceResult result;

    // urls usually carry the most context, so they are classified before shorter domain or ip artifacts.
    // url analysis prefers easy-to-explain buckets instead of pretending to do full reputation work here.
    for (const auto& url : indicators.urls)
    {
        const std::string lower = bl::common::ToLowerCopy(url);
        if (lower.find("aka.ms") != std::string::npos || lower.find("microsoft.com") != std::string::npos || lower.find("google.com") != std::string::npos)
            AddFinding(result, url, "Trusted infrastructure", "Matches a common vendor or CDN domain");
        else if (lower.find("raw") != std::string::npos || lower.find("paste") != std::string::npos || lower.find("discord") != std::string::npos)
            AddFinding(result, url, "Delivery-oriented infrastructure", "Textual pattern resembles payload hosting or direct content delivery");
        else
            AddFinding(result, url, "Unclassified network artifact", "No clear allow-list or high-risk pattern matched");
    }

    // domains are handled separately because they often come from noisier extraction paths than full urls.
    // domains often need softer wording because extraction quality varies widely across samples.
    for (const auto& domain : indicators.domains)
    {
        const std::string lower = bl::common::ToLowerCopy(domain);
        if (lower.find("microsoft") != std::string::npos || lower.find("google") != std::string::npos || lower.find("github") != std::string::npos)
            AddFinding(result, domain, "Known service domain", "Domain name resembles a widely used legitimate platform");
        else if (std::count(lower.begin(), lower.end(), '.') == 0)
            AddFinding(result, domain, "Incomplete domain artifact", "Extracted token may be truncated and needs analyst review");
        else
            AddFinding(result, domain, "Unknown domain", "No contextual allow-list matched");
    }

    // hard-coded ips are blunt indicators, but they still help distinguish local tooling from external infrastructure.
    for (const auto& ip : indicators.ips)
    {
        const bool privateRange = ip.rfind("10.", 0) == 0 || ip.rfind("192.168.", 0) == 0 || ip.rfind("172.16.", 0) == 0 || ip.rfind("172.17.", 0) == 0 || ip.rfind("127.", 0) == 0;
        if (privateRange)
            AddFinding(result, ip, "Private or local address", "The IP points to a non-routable or loopback range");
        else
            AddFinding(result, ip, "Raw external IP", "Hard-coded public IPs can indicate direct infrastructure usage");
    }

    // commands add operational context that simple network artifacts cannot provide on their own.
    for (const auto& command : indicators.suspiciousCommands)
    {
        const std::string lower = bl::common::ToLowerCopy(command);
        if (lower.find("powershell") != std::string::npos || lower.find("cmd.exe") != std::string::npos)
            AddFinding(result, command, "Execution utility", "Command references a common script or shell launcher");
        else if (lower.find("schtasks") != std::string::npos || lower.find("reg add") != std::string::npos)
            AddFinding(result, command, "Persistence-related artifact", "Command matches a common persistence workflow");
    }

    return result;
}
