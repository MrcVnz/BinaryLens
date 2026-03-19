#include "core/behavior_simulator.h"

#include <algorithm>

#include "analyzers/import_analyzer.h"
#include "analyzers/indicator_extractor.h"
#include "analyzers/pe_analyzer.h"
#include "scanners/file_scanner.h"
// behavior synthesis that translates low-level evidence into likely runtime actions.

// helper logic that turns dispersed signals into concise behavior narratives.
namespace
{
    void AddUnique(std::vector<std::string>& items, const std::string& value)
    {
        if (value.empty())
            return;
        if (std::find(items.begin(), items.end(), value) == items.end())
            items.push_back(value);
    }
}

SimulatedBehaviorReport BuildSimulatedBehaviorReport(const FileInfo& info, const Indicators& indicators, const ImportAnalysisResult& importInfo, const PEAnalysisResult& peInfo)
{
    SimulatedBehaviorReport out;

    if (!indicators.urls.empty() || std::find(importInfo.capabilityClusters.begin(), importInfo.capabilityClusters.end(), "Network Beaconing / C2") != importInfo.capabilityClusters.end())
        AddUnique(out.behaviors, "Would likely attempt outbound HTTP or HTTPS communication");
    if (indicators.hasDownloaderTraits)
        AddUnique(out.behaviors, "Would likely retrieve a remote payload or stage additional content");
    if (indicators.hasPersistenceTraits)
        AddUnique(out.behaviors, "Would likely try to establish persistence through registry, startup, or scheduled task style artifacts");
    if (indicators.hasInjectionTraits || std::find(importInfo.capabilityClusters.begin(), importInfo.capabilityClusters.end(), "Process Injection") != importInfo.capabilityClusters.end())
        AddUnique(out.behaviors, "Would likely interact with another process memory space or loader-style routine");
    if (indicators.hasEvasionTraits || peInfo.hasAntiDebugIndicators)
        AddUnique(out.behaviors, "Would likely perform debugger or analysis-environment checks before continuing");
    if (indicators.hasCredentialTheftTraits)
        AddUnique(out.behaviors, "Would likely enumerate local credential or browser-secret related artifacts");
    if (indicators.hasRansomwareTraits)
        AddUnique(out.behaviors, "Would likely tamper with recovery options or backup-related system state");
    if (info.archiveInspectionPerformed && (info.archiveContainsExecutable || info.archiveContainsScript))
        AddUnique(out.behaviors, "Archive payload staging suggests delivery of an executable or script after extraction");

    if (out.behaviors.empty())
        AddUnique(out.analystNotes, "No strong simulated runtime narrative was derived from current static signals");
    else
        AddUnique(out.analystNotes, "Simulated behaviors are static inferences and not proof of execution");

    if (!out.behaviors.empty())
    {
        AddUnique(out.timelineSteps, "LOAD -> Parse entrypoint and imports");
        if (indicators.hasEvasionTraits || peInfo.hasAntiDebugIndicators)
            AddUnique(out.timelineSteps, "CHECK -> Anti-debug / analysis awareness");
        if (indicators.hasDownloaderTraits || !indicators.urls.empty())
            AddUnique(out.timelineSteps, "NETWORK -> Contact remote host or stage payload");
        if (indicators.hasInjectionTraits)
            AddUnique(out.timelineSteps, "EXECUTE -> Loader / process interaction");
        if (indicators.hasPersistenceTraits)
            AddUnique(out.timelineSteps, "PERSIST -> Registry / startup style foothold");
    }

    return out;
}
