#include "core/behavior_simulator.h"
#include "common/string_utils.h"

#include <algorithm>
#include <map>

#include "analyzers/import_analyzer.h"
#include "analyzers/indicator_extractor.h"
#include "analyzers/pe_analyzer.h"
#include "scanners/file_scanner.h"

// behavior synthesis that translates low-level evidence into likely runtime actions.

namespace
{
    // timeline buckets keep the output ordered even when several engines contribute to the same stage.
    void AddStep(std::map<int, std::vector<std::string>>& steps, int order, const std::string& value)
    // adds this detail through one gate so duplicate or noisy output stays under control.
    {
        bl::common::AddUnique(steps[order], value, 4);
    }

    // cluster checks stay local so the simulator reads closer to a narrative than a lookup table.
    bool HasCluster(const ImportAnalysisResult& importInfo, const std::string& cluster)
    // answers this has cluster check in one place so the surrounding logic stays readable.
    {
        return std::find(importInfo.capabilityClusters.begin(), importInfo.capabilityClusters.end(), cluster) != importInfo.capabilityClusters.end();
    }

    // commands are scanned case-insensitively because extracted text can arrive in mixed casing.
    bool HasCommandHint(const Indicators& indicators, const std::string& token)
    // answers this has command hint check in one place so the surrounding logic stays readable.
    {
        const std::string target = bl::common::ToLowerCopy(token);
        for (const auto& command : indicators.suspiciousCommands)
        {
            if (bl::common::ToLowerCopy(command).find(target) != std::string::npos)
                return true;
        }
        return false;
    }
}

// this derives a likely execution path and keeps container staging, decode steps, and resolver phases in the same flow.
// this derives a likely execution path and keeps container staging, decode steps, and resolver phases in the same flow.
SimulatedBehaviorReport BuildSimulatedBehaviorReport(const FileInfo& info, const Indicators& indicators, const ImportAnalysisResult& importInfo, const PEAnalysisResult& peInfo)
// builds this behavior narrative fragment in one place so the surrounding code can stay focused on flow.
{
    SimulatedBehaviorReport out;

    // each boolean below stands in for a broader behavior family used later in both the summary and the timeline.
    const bool dynamicResolution = HasCluster(importInfo, "Dynamic API Resolution");
    const bool networking = !indicators.urls.empty() || HasCluster(importInfo, "Network Beaconing / C2") || indicators.hasDownloaderTraits;
    const bool deobfuscationHints = !indicators.base64Blobs.empty() ||
        HasCommandHint(indicators, "frombase64string") ||
        HasCommandHint(indicators, "fromcharcode") ||
        HasCommandHint(indicators, "invoke-expression");
    const bool archiveStaging = info.archiveInspectionPerformed &&
        (info.archiveContainsExecutable || info.archiveContainsScript || info.archiveContainsShortcut || info.archiveContainsNestedArchive);

    // summary behaviors favor readable analyst phrasing over exact execution claims.
    if (archiveStaging)
        bl::common::AddUnique(out.behaviors, "Would likely expose or extract staged content from an archive container", 12);
    if (deobfuscationHints)
        bl::common::AddUnique(out.behaviors, "Would likely reconstruct or decode staged strings before the main action", 12);
    if (networking)
        bl::common::AddUnique(out.behaviors, "Would likely attempt outbound HTTP or HTTPS communication", 12);
    if (indicators.hasDownloaderTraits)
        bl::common::AddUnique(out.behaviors, "Would likely retrieve a remote payload or stage additional content", 12);
    if (dynamicResolution)
        bl::common::AddUnique(out.behaviors, "Would likely resolve exports dynamically before executing a loader or injection path", 12);
    if (indicators.hasPersistenceTraits || HasCluster(importInfo, "Persistence"))
        bl::common::AddUnique(out.behaviors, "Would likely try to establish persistence through registry, startup, or scheduled task style artifacts", 12);
    if (indicators.hasInjectionTraits || HasCluster(importInfo, "Process Injection"))
        bl::common::AddUnique(out.behaviors, "Would likely interact with another process memory space or loader-style routine", 12);
    if (indicators.hasEvasionTraits || peInfo.hasAntiDebugIndicators || HasCluster(importInfo, "Anti-Debug / Anti-Analysis"))
        bl::common::AddUnique(out.behaviors, "Would likely perform debugger or analysis-environment checks before continuing", 12);
    if (indicators.hasCredentialTheftTraits || HasCluster(importInfo, "Discovery / Secret Access"))
        bl::common::AddUnique(out.behaviors, "Would likely enumerate browser, token, credential, or local secret artifacts", 12);
    if (indicators.hasRansomwareTraits)
        bl::common::AddUnique(out.behaviors, "Would likely tamper with recovery options or backup-related system state", 12);

    // an empty behavior list is still worth annotating so the analyst knows the simulator did run.
    if (out.behaviors.empty())
        bl::common::AddUnique(out.analystNotes, "No strong simulated runtime narrative was derived from current static signals", 4);
    else
        bl::common::AddUnique(out.analystNotes, "Simulated behaviors are static inferences and not proof of execution", 4);

    // timeline order is intentionally coarse because this is a reasoning aid, not an emulator trace.
    std::map<int, std::vector<std::string>> orderedTimeline;
    AddStep(orderedTimeline, 10, "LOAD -> Parse entrypoint, imports, and embedded resources");

    if (archiveStaging)
        AddStep(orderedTimeline, 15, "STAGE -> Extract or expose archive-contained payload material");

    // later stages are additive, so several behaviors can coexist in the same inferred storyline.

    if (indicators.hasEvasionTraits || peInfo.hasAntiDebugIndicators || HasCluster(importInfo, "Anti-Debug / Anti-Analysis"))
        AddStep(orderedTimeline, 20, "CHECK -> Anti-debug or environment-awareness checks");

    if (deobfuscationHints)
        AddStep(orderedTimeline, 25, "DECODE -> Rebuild encoded strings or staged script fragments");

    if (networking)
        AddStep(orderedTimeline, 30, "NETWORK -> Contact remote host, beacon, or stage payload");

    if (indicators.hasCredentialTheftTraits || HasCluster(importInfo, "Discovery / Secret Access"))
        AddStep(orderedTimeline, 35, "DISCOVER -> Query browser, token, credential, or system-secret stores");

    if (dynamicResolution)
        AddStep(orderedTimeline, 38, "RESOLVE -> Walk exports or resolve apis dynamically before pivoting");

    if (indicators.hasInjectionTraits || HasCluster(importInfo, "Process Injection"))
        AddStep(orderedTimeline, 40, "EXECUTE -> Interact with another process or loader path");
    else if (HasCluster(importInfo, "Execution / LOLBin Launching"))
        AddStep(orderedTimeline, 40, "EXECUTE -> Launch a secondary system binary or helper process");

    if (indicators.hasPersistenceTraits || HasCluster(importInfo, "Persistence"))
        AddStep(orderedTimeline, 50, "PERSIST -> Establish startup, service, or autorun foothold");

    if (indicators.hasRansomwareTraits)
        AddStep(orderedTimeline, 60, "IMPACT -> Tamper with recovery or destructive system state");

    for (const auto& [_, steps] : orderedTimeline)
    {
        for (const auto& step : steps)
            bl::common::AddUnique(out.timelineSteps, step, 12);
    }

    return out;
}
