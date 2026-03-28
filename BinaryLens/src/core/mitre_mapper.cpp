#include "core/mitre_mapper.h"

#include "common/string_utils.h"
#include "analyzers/import_analyzer.h"
#include "analyzers/indicator_extractor.h"
#include "analyzers/pe_analyzer.h"
#include "scanners/file_scanner.h"

namespace
{
    void AddTechnique(std::vector<std::string>& out, const std::string& value)
    {
        bl::common::AddUnique(out, value, 16);
    }

    bool HasCluster(const ImportAnalysisResult& importInfo, const std::string& cluster)
    {
        for (const auto& value : importInfo.capabilityClusters)
        {
            if (value == cluster)
                return true;
        }
        return false;
    }

    bool HasCommandToken(const Indicators& indicators, const std::string& token)
    {
        const std::string loweredToken = bl::common::ToLowerCopy(token);
        for (const auto& command : indicators.suspiciousCommands)
        {
            if (bl::common::ToLowerCopy(command).find(loweredToken) != std::string::npos)
                return true;
        }
        return false;
    }
}

// mapping stays conservative: techniques are only added when the static facts line up with a recognizable behavior path.
std::vector<std::string> BuildMitreTechniqueLabels(const FileInfo& info,
                                                   const Indicators& indicators,
                                                   const ImportAnalysisResult& importInfo,
                                                   const PEAnalysisResult& peInfo)
{
    std::vector<std::string> labels;

    if (indicators.hasInjectionTraits || HasCluster(importInfo, "Process Injection"))
        AddTechnique(labels, "T1055 - Process Injection");

    if (indicators.hasCredentialTheftTraits)
        AddTechnique(labels, "T1555 - Credentials from Password Stores");

    if (indicators.hasPersistenceTraits || HasCluster(importInfo, "Persistence"))
        AddTechnique(labels, "T1547 - Boot or Logon Autostart Execution");

    if (indicators.hasDownloaderTraits || HasCluster(importInfo, "Network Beaconing / C2") || !indicators.urls.empty())
        AddTechnique(labels, "T1071 - Application Layer Protocol");
    if (indicators.hasDownloaderTraits && !indicators.urls.empty())
        AddTechnique(labels, "T1105 - Ingress Tool Transfer");

    if (indicators.hasEvasionTraits || peInfo.hasAntiDebugIndicators || HasCluster(importInfo, "Anti-Debug / Anti-Analysis"))
        AddTechnique(labels, "T1622 - Debugger Evasion");

    if (peInfo.possiblePackedFile || !indicators.base64Blobs.empty())
        AddTechnique(labels, "T1027 - Obfuscated or Compressed Files and Information");

    if (HasCluster(importInfo, "Dynamic API Resolution"))
        AddTechnique(labels, "T1027.007 - Dynamic API Resolution");

    if (!indicators.base64Blobs.empty() || HasCommandToken(indicators, "frombase64string") || HasCommandToken(indicators, "fromcharcode"))
        AddTechnique(labels, "T1140 - Deobfuscate/Decode Files or Information");

    if (indicators.hasRansomwareTraits)
        AddTechnique(labels, "T1490 - Inhibit System Recovery");

    if (info.archiveInspectionPerformed && info.archiveContainsShortcut)
        AddTechnique(labels, "T1204.002 - Malicious File");

    if (info.archiveInspectionPerformed && info.archiveContainsLureAndExecutablePattern)
        AddTechnique(labels, "T1566.001 - Spearphishing Attachment");

    if (!indicators.suspiciousCommands.empty())
        AddTechnique(labels, "T1059 - Command and Scripting Interpreter");
    if (HasCommandToken(indicators, "powershell"))
        AddTechnique(labels, "T1059.001 - PowerShell");
    if (HasCommandToken(indicators, "cmd") || HasCommandToken(indicators, "cmd.exe"))
        AddTechnique(labels, "T1059.003 - Windows Command Shell");

    if (HasCluster(importInfo, "Execution / LOLBin Launching"))
        AddTechnique(labels, "T1218 - System Binary Proxy Execution");

    if (info.doubleExtensionSuspicious || info.archiveContainsSuspiciousDoubleExtension)
        AddTechnique(labels, "T1036.007 - Double File Extension");

    return labels;
}
