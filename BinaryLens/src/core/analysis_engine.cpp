#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <future>
#include <initializer_list>
#include <utility>

#include "asm/asm_bridge.h"
#include "analyzers/import_analyzer.h"
#include "analyzers/embedded_payload_analyzer.h"
#include "analyzers/indicator_extractor.h"
#include "analyzers/pe_analyzer.h"
#include "analyzers/script_abuse_analyzer.h"
#include "analyzers/url_analyzer.h"
#include "core/analysis_engine.h"
#include "core/analysis_control.h"
#include "core/advanced_analysis.h"
#include "core/analysis_cache.h"
#include "core/behavior_simulator.h"
#include "core/risk_engine.h"
#include "core/yara_engine.h"
#include "core/evasion_engine.h"
#include "core/confidence_engine.h"
#include "core/deobfuscation_engine.h"
#include "core/evidence_calibrator.h"
#include "core/ioc_intelligence.h"
#include "core/ml_classifier.h"
#include "core/memory_scanner.h"
#include "core/mitre_mapper.h"
#include "core/plugin_engine.h"
#include "core/task_scheduler.h"
#include "core/verdict_engine.h"
#include "scanners/file_scanner.h"
#include "scanners/url_scanner.h"
#include "services/api_client.h"
#include "services/signature_checker.h"
#include "common/string_utils.h"
// main orchestration pipeline that fans work out to specialized engines and merges the results.

// formatting, scoring guards, and context helpers used while merging engine outputs.
namespace
{
    constexpr std::uint64_t kHeavyFileThreshold = 512ull * 1024ull * 1024ull;
    template <typename Fn>
    auto MeasureTaskMs(Fn&& fn)
    {
        using ResultType = decltype(fn());
        const auto started = std::chrono::steady_clock::now();
        ResultType value = fn();
        const auto finished = std::chrono::steady_clock::now();
        const double elapsedMs = std::chrono::duration<double, std::milli>(finished - started).count();
        return std::make_pair(std::move(value), elapsedMs);
    }

    std::string FormatMs(double value)
    {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(value >= 100.0 ? 0 : 1) << value << " ms";
        return oss.str();
    }

    std::string FormatDouble(double value, int decimals = 2)
    {
        std::ostringstream stream;
        stream << std::fixed << std::setprecision(decimals) << value;
        return stream.str();
    }

    void AddLine(std::string& out, const std::string& line)
    {
        out += line;
        out += "\r\n";
    }

    void AddSection(std::string& out, const std::string& title)
    {
        out += "\r\n";
        AddLine(out, title);
    }

    std::string HumanizeDomainContextTag(const std::string& tag)
    {
        if (tag == "trusted_domain")
            return "Trusted domain family context detected";
        if (tag == "shared_edge_infrastructure")
            return "Shared edge, cdn, or reverse-proxy infrastructure detected";
        if (tag == "established_provider_context")
            return "Established provider or large-platform ownership context detected";
        if (tag == "dynamic_dns")
            return "Dynamic dns style infrastructure detected";
        if (tag == "double_encoded")
            return "Double-encoded url components were observed";
        if (tag == "file_share_provider")
            return "File-sharing or paste-style platform context detected";
        if (tag == "internal_or_local_target")
            return "Internal, lab, or local-scope target context detected";
        if (tag == "brand_impersonation")
            return "Brand impersonation context detected";
        if (tag == "cross_host_redirect")
            return "Cross-host redirect context detected";
        return tag;
    }

    void AddReasonIfMissing(std::vector<std::string>& reasons, const std::string& reason)
    {
        if (std::find(reasons.begin(), reasons.end(), reason) == reasons.end())
            reasons.push_back(reason);
    }

    void ClampScore(int& value)
    {
        if (value < 0)
            value = 0;
        if (value > 100)
            value = 100;
    }

    std::string ToLowerCopy(std::string value)
    {
        return bl::common::ToLowerCopy(std::move(value));
    }

    bool ContainsText(const std::string& haystack, const std::string& needle)
    {
        return ToLowerCopy(haystack).find(ToLowerCopy(needle)) != std::string::npos;
    }

    bool IsTrustedPublisher(const SignatureCheckResult& sigInfo)
    {
        if (!sigInfo.isSigned || !sigInfo.signatureValid || !sigInfo.hasPublisher)
            return false;
        const std::string publisher = ToLowerCopy(sigInfo.publisher);
        static const char* trusted[] = {
            "microsoft", "google", "adobe", "mozilla", "nvidia", "intel", "vmware",
            "oracle", "apple", "amazon", "cloudflare", "citrix", "docker", "jetbrains"
        };
        for (const char* token : trusted)
        {
            if (publisher.find(token) != std::string::npos)
                return true;
        }
        return false;
    }

    bool IsLikelyLegitimateBootstrapper(const FileInfo& info, const SignatureCheckResult& sigInfo, const PEAnalysisResult& peInfo, const Indicators& indicators)
    {
        if (!sigInfo.isSigned || !sigInfo.signatureValid)
            return false;
        if (!peInfo.isPE || !peInfo.hasOverlay)
            return false;
        const std::string pathLower = ToLowerCopy(info.path);
        const std::string nameLower = ToLowerCopy(info.name);
        if (indicators.hasInstallerTraits)
            return true;
        if (nameLower.find("setup") != std::string::npos || nameLower.find("installer") != std::string::npos || nameLower.find("bootstrap") != std::string::npos)
            return true;
        if (ContainsText(sigInfo.publisher, "microsoft") && peInfo.overlaySize > 512 * 1024)
            return true;
        return pathLower.find("visualstudio") != std::string::npos || pathLower.find("setup") != std::string::npos;
    }

    int ScaleStringOnlyRisk(int baseWeight, unsigned int evidenceCount, bool analysisContext)
    {
        int scaled = baseWeight;
        if (evidenceCount <= 1)
            scaled = std::max(2, baseWeight / 2);
        else if (evidenceCount == 2)
            scaled = static_cast<int>(std::max(3, (baseWeight * 3) / 4));
        if (analysisContext)
            scaled = std::max(1, scaled / 3);
        return scaled;
    }

    int ScaleCorrelationRisk(int baseWeight, bool analysisContext, bool trustedPublisher, bool likelyLegitimateBootstrapper)
    {
        int scaled = baseWeight;
        if (analysisContext)
            scaled = std::max(1, scaled / 3);
        if (trustedPublisher)
            scaled = std::max(1, scaled / 2);
        if (likelyLegitimateBootstrapper)
            scaled = std::max(1, scaled / 2);
        return scaled;
    }

    // ambiguous loader-style traits should be strongly damped when trusted signed software matches installer semantics.
    int ScaleAmbiguousExecutionRisk(int baseWeight,
                                    bool trustedSignedPe,
                                    bool trustedPublisher,
                                    bool likelyLegitimateBootstrapper,
                                    bool developerAnalysisContext)
    {
        int scaled = baseWeight;
        if (developerAnalysisContext)
            scaled = std::max(1, scaled / 2);
        if (trustedSignedPe)
            scaled = std::max(1, scaled / 3);
        else if (trustedPublisher)
            scaled = std::max(1, (scaled * 2) / 3);
        if (likelyLegitimateBootstrapper)
            scaled = std::max(1, scaled / 2);
        return scaled;
    }

    bool LooksLikeLocalDevelopmentBuild(const FileInfo& info)
    {
        const std::string pathLower = ToLowerCopy(info.path);
        return pathLower.find("\\debug\\") != std::string::npos ||
               pathLower.find("\\release\\") != std::string::npos ||
               pathLower.find("\\x64\\debug\\") != std::string::npos ||
               pathLower.find("\\x64\\release\\") != std::string::npos ||
               pathLower.find("onedrive\\documentos") != std::string::npos ||
               pathLower.find("source\\repos") != std::string::npos;
    }

    bool IsDeveloperOrSecurityToolContext(const FileInfo& info, const Indicators& indicators)
    {
        if (indicators.hasSecurityAnalysisContext)
            return true;
        const std::string pathLower = ToLowerCopy(info.path);
        const std::string nameLower = ToLowerCopy(info.name);
        static const char* tokens[] = {
            "binarylens", "scanner", "analyzer", "sandbox", "malware", "threat", "reverse", "forensics"
        };
        for (const char* token : tokens)
        {
            if (pathLower.find(token) != std::string::npos || nameLower.find(token) != std::string::npos)
                return true;
        }
        return false;
    }

    bool HasEmbeddedLibraryToken(const Indicators& indicators, const std::string& token)
    {
        for (const auto& label : indicators.embeddedLibraries)
        {
            if (ContainsText(label, token))
                return true;
        }
        return false;
    }

    std::vector<std::string> BuildContextTags(bool developerAnalysisContext, bool localDevelopmentBuild, bool trustedPublisher, bool likelyLegitimateBootstrapper)
    {
        std::vector<std::string> tags;
        if (developerAnalysisContext)
            tags.push_back("Security / developer tool context detected");
        if (localDevelopmentBuild)
            tags.push_back("Local development build path detected");
        if (trustedPublisher)
            tags.push_back("Trusted publisher context detected");
        if (likelyLegitimateBootstrapper)
            tags.push_back("Installer / bootstrapper context detected");
        return tags;
    }

    std::vector<std::string> BuildYaraMatchLabels(const YaraScanResult& yara)
    {
        std::vector<std::string> out;
        for (const auto& match : yara.matches)
        {
            std::string line = match.ruleName;
            if (!match.matchedTokens.empty())
            {
                line += " (";
                for (std::size_t i = 0; i < match.matchedTokens.size(); ++i)
                {
                    line += match.matchedTokens[i];
                    if (i + 1 < match.matchedTokens.size())
                        line += ", ";
                }
                line += ")";
            }
            if (!match.conditionSummary.empty())
                line += " [condition: " + match.conditionSummary + "]";
            out.push_back(line);
        }
        return out;
    }

    std::vector<std::string> BuildPluginLabels(const std::vector<PluginMatch>& matches)
    {
        std::vector<std::string> out;
        for (const auto& match : matches)
            out.push_back(match.pluginName + ": " + match.label + " (+" + std::to_string(match.scoreBoost) + ")");
        return out;
    }

    std::string FormatEtaSeconds(int totalSeconds)
    {
        if (totalSeconds < 0)
            return "Calculating...";
        const int hours = totalSeconds / 3600;
        const int minutes = (totalSeconds % 3600) / 60;
        const int seconds = totalSeconds % 60;
        std::ostringstream oss;
        if (hours > 0)
            oss << hours << "h ";
        if (hours > 0 || minutes > 0)
            oss << minutes << "m ";
        oss << seconds << "s";
        return oss.str();
    }

    std::string BuildReasonsBlock(const std::vector<std::string>& reasons)
    {
        std::string result;
        if (reasons.empty())
        {
            AddLine(result, "- No notable indicators");
            return result;
        }

        for (const auto& reason : reasons)
            AddLine(result, "- " + reason);
        return result;
    }

    bool ContainsAnyToken(const std::string& value, const std::initializer_list<const char*>& tokens)
    {
        const std::string lowered = ToLowerCopy(value);
        for (const char* token : tokens)
        {
            if (lowered.find(token) != std::string::npos)
                return true;
        }
        return false;
    }

    std::vector<std::string> BuildCondensedReasons(const std::vector<std::string>& reasons)
    {
        std::vector<std::string> condensed;
        bool keptExecutionCapability = false;
        bool keptAntiAnalysisCapability = false;
        bool keptPackingSignal = false;
        bool keptEntrypointSignal = false;
        bool keptScriptSignal = false;

        for (const auto& reason : reasons)
        {
            if (reason.empty())
                continue;

            if (ContainsAnyToken(reason, {"dynamic api resolution", "discovery / secret access"}))
            {
                if (keptExecutionCapability)
                    continue;
                keptExecutionCapability = true;
            }
            else if (ContainsAnyToken(reason, {"anti-debug", "anti-analysis", "evasion"}))
            {
                if (keptAntiAnalysisCapability)
                    continue;
                keptAntiAnalysisCapability = true;
            }
            else if (ContainsAnyToken(reason, {"packer-like", "overlay data detected"}))
            {
                if (keptPackingSignal)
                    continue;
                keptPackingSignal = true;
            }
            else if (ContainsAnyToken(reason, {"stub-like entrypoint", "entrypoint bytes look shellcode-like", "entrypoint asm"}))
            {
                if (keptEntrypointSignal)
                    continue;
                keptEntrypointSignal = true;
            }
            else if (ContainsAnyToken(reason, {"script-capable"}))
            {
                if (keptScriptSignal)
                    continue;
                keptScriptSignal = true;
            }

            condensed.push_back(reason);
        }

        return condensed;
    }

    // builds a compact executive summary so the report starts with the main decision story.
    std::vector<std::string> BuildKeyEvidenceOverview(const PEAnalysisResult& peInfo,
                                                      const ImportAnalysisResult& importInfo,
                                                      const ScriptAbuseAnalysisResult& scriptAbuseInfo,
                                                      const EmbeddedPayloadAnalysisResult& embeddedPayloadInfo,
                                                      const AdvancedAnalysisSummary& advancedSummary,
                                                      const SignatureCheckResult& sigInfo,
                                                      int finalRiskScore,
                                                      const std::string& finalVerdict)
    {
        std::vector<std::string> overview;

        overview.push_back("Verdict " + finalVerdict + " at risk score " + std::to_string(finalRiskScore) + "%");

        if (peInfo.isPE)
        {
            if (peInfo.packerScore >= 12 || peInfo.hasOverlay)
                overview.push_back("PE structure shows packing or staged overlay traits");
            if (peInfo.hasTlsCallbacks)
                overview.push_back("TLS callbacks are present in the executable structure");
            if (!peInfo.asmEntrypointProfileSummary.empty())
                overview.push_back("Entrypoint profiling suggests " + peInfo.asmEntrypointProfileSummary);
        }

        if (importInfo.suspiciousImportCount > 0)
            overview.push_back("Import analysis surfaced " + std::to_string(importInfo.suspiciousImportCount) + " suspicious API references");

        if (embeddedPayloadInfo.foundEmbeddedPE)
        {
            const std::string lead = embeddedPayloadInfo.validatedEmbeddedPE
                ? "A structurally valid embedded PE candidate was identified inside the scanned sample"
                : "An embedded PE-like marker was identified inside the scanned sample";
            overview.push_back(lead);
        }
        if (embeddedPayloadInfo.foundShellcodeLikeBlob)
        {
            const std::string lead = embeddedPayloadInfo.likelyCompressedNoise
                ? "Low-level shellcode heuristics fired inside a compressed-looking region"
                : "A shellcode-like raw code window was detected outside the main entrypoint path";
            overview.push_back(lead);
        }
        else if (embeddedPayloadInfo.suspiciousWindowCount >= 3)
        {
            const std::string lead = embeddedPayloadInfo.likelyCompressedNoise
                ? "Multiple suspicious raw code windows were clustered, but the byte distribution looks archive-compressed"
                : "Multiple suspicious raw code windows were clustered in the sampled content";
            overview.push_back(lead);
        }
        if (!embeddedPayloadInfo.strongestProfileSummary.empty())
            overview.push_back("Embedded payload profiling suggests " + embeddedPayloadInfo.strongestProfileSummary);
        if (!advancedSummary.embeddedPayloadDisposition.empty())
            overview.push_back("Embedded payload disposition: " + advancedSummary.embeddedPayloadDisposition);
        if (scriptAbuseInfo.analyzed && scriptAbuseInfo.score > 0)
            overview.push_back("Script abuse scoring found interpreter or staging traits in sampled content");

        if (sigInfo.isSigned && !sigInfo.signatureValid)
            overview.push_back("The sample is signed, but the signature did not validate cleanly");

        if (!advancedSummary.yaraMatches.empty())
            overview.push_back("Rule-backed matching contributed " + std::to_string(advancedSummary.yaraMatches.size()) + " YARA-like hit(s)");

        // cross-engine correlation is capped so repeated narratives do not snowball the score.
        if (!advancedSummary.correlationHighlights.empty())
            overview.push_back("Cross-engine correlation linked multiple indicators into a higher-confidence story");

        if (!advancedSummary.legitimateContext.empty())
            overview.push_back("Legitimate context markers were also preserved to reduce overstatement");

        return overview;
    }

    // extracts the strongest raw technical findings without repeating every engine section verbatim.
    std::vector<std::string> BuildPrimaryTechnicalFindings(const FileInfo& info,
                                                           const PEAnalysisResult& peInfo,
                                                           const ImportAnalysisResult& importInfo,
                                                           const ScriptAbuseAnalysisResult& scriptAbuseInfo,
                                                           const EmbeddedPayloadAnalysisResult& embeddedPayloadInfo,
                                                           const AdvancedAnalysisSummary& advancedSummary)
    {
        std::vector<std::string> findings;

        if (peInfo.isPE)
        {
            if (peInfo.hasOverlay)
                findings.push_back("Overlay data is present in the PE layout (" + std::to_string(peInfo.overlaySize) + " bytes)");
            if (peInfo.hasTlsCallbacks)
                findings.push_back("TLS callbacks are present and may shift execution before the main entrypoint");
            if (!peInfo.asmEntrypointProfileSummary.empty())
                findings.push_back("Entrypoint profiling indicates " + peInfo.asmEntrypointProfileSummary);
        }

        if (importInfo.suspiciousImportCount > 0)
            findings.push_back("Import analysis flagged " + std::to_string(importInfo.suspiciousImportCount) + " suspicious API reference(s)");

        if (info.archiveInspectionPerformed && info.archiveContainsExecutable)
            findings.push_back("Archive inspection found executable payload material inside the container");

        if (scriptAbuseInfo.analyzed && scriptAbuseInfo.score > 0)
            findings.push_back("Script abuse scoring surfaced interpreter, staging, or encoded payload traits");

        if (embeddedPayloadInfo.foundEmbeddedPE)
        {
            const std::string prefix = embeddedPayloadInfo.validatedEmbeddedPE
                ? "Embedded payload scanning located a structurally valid internal PE header at offset "
                : "Embedded payload scanning located an internal PE-like marker at offset ";
            findings.push_back(prefix + std::to_string(static_cast<unsigned long long>(embeddedPayloadInfo.embeddedPEOffset)));
        }
        if (embeddedPayloadInfo.foundShellcodeLikeBlob)
        {
            const std::string prefix = embeddedPayloadInfo.likelyCompressedNoise
                ? "Embedded payload scanning found a shellcode-like code region, but the surrounding bytes still look compression-heavy, at offset "
                : "Embedded payload scanning found a shellcode-like code region at offset ";
            findings.push_back(prefix + std::to_string(static_cast<unsigned long long>(embeddedPayloadInfo.shellcodeOffset)));
        }
        else if (embeddedPayloadInfo.suspiciousWindowCount >= 3)
        {
            const std::string suffix = embeddedPayloadInfo.likelyCompressedNoise
                ? " suspicious raw code windows in a compressed-looking sampled region"
                : " suspicious raw code windows in the sampled region";
            findings.push_back("Embedded payload scanning clustered " + std::to_string(embeddedPayloadInfo.suspiciousWindowCount) + suffix);
        }
        if (!embeddedPayloadInfo.strongestProfileSummary.empty())
            findings.push_back("Embedded payload opcode profiling indicates " + embeddedPayloadInfo.strongestProfileSummary);
        if (!embeddedPayloadInfo.maskedPatternFindings.empty())
            findings.push_back("Masked opcode scanning surfaced explicit loader-style byte motifs inside the sampled content");
        if (!advancedSummary.embeddedPayloadDisposition.empty())
            findings.push_back("Embedded payload reliability assessment: " + advancedSummary.embeddedPayloadDisposition);

        if (!advancedSummary.yaraMatches.empty())
            findings.push_back("YARA-like detection contributed " + std::to_string(advancedSummary.yaraMatches.size()) + " rule-backed match(es)");
        if (!advancedSummary.evasionFindings.empty())
            findings.push_back("Evasion analysis surfaced anti-analysis or stealth-oriented traits");
        if (!advancedSummary.iocIntelligenceSummary.empty())
            findings.push_back("IOC intelligence extracted network or host artifacts worth pivoting on");

        return findings;
    }

    // captures analyst-facing caveats and context that can soften or sharpen interpretation.
    std::vector<std::string> BuildAnalystNotes(const AdvancedAnalysisSummary& advancedSummary,
                                               const SignatureCheckResult& sigInfo,
                                               bool trustedPublisher,
                                               bool likelyLegitimateBootstrapper)
    {
        std::vector<std::string> notes;

        if (sigInfo.isSigned && !sigInfo.signatureValid)
            notes.push_back("The sample carries a signature artifact, but validation did not complete cleanly");
        if (trustedPublisher)
            notes.push_back("Trusted publisher context is present and should be weighed against suspicious heuristics");
        if (likelyLegitimateBootstrapper)
            notes.push_back("Installer or bootstrapper context can explain overlay and staging-style structure");
        for (const auto& item : advancedSummary.analysisContextTags)
        {
            if (!item.empty())
                notes.push_back(item);
        }
        for (const auto& item : advancedSummary.legitimateContext)
        {
            if (!item.empty())
                notes.push_back(item);
        }
        for (const auto& item : advancedSummary.evidenceCalibrationNotes)
        {
            if (!item.empty())
                notes.push_back(item);
        }

        return notes;
    }

    // explains which engines most directly support the final verdict and confidence level.
    std::vector<std::string> BuildDecisionBasis(const std::vector<std::string>& finalReasons,
                                                const ConfidenceResult& confidence,
                                                const AdvancedAnalysisSummary& advancedSummary,
                                                bool hasReputationContext)
    {
        std::vector<std::string> basis;
        basis.push_back("Confidence level: " + confidence.label + " (" + confidence.rationale + ")");
        if (!advancedSummary.correlationHighlights.empty())
            basis.push_back("Cross-engine correlation produced a coherent multi-signal explanation");
        if (!advancedSummary.yaraMatches.empty())
            basis.push_back("Rule-backed detections contributed direct pattern evidence");
        if (!advancedSummary.simulatedBehaviors.empty())
            basis.push_back("Behavior simulation added an execution narrative for the observed indicators");
        if (hasReputationContext)
            basis.push_back("Reputation context was available and factored into the final decision");
        for (const auto& item : finalReasons)
        {
            if (!item.empty())
                basis.push_back(item);
            if (basis.size() >= 8)
                break;
        }
        return basis;
    }

    void AddTopList(std::string& out, const std::vector<std::string>& items, std::size_t maxItems)
    {
        std::size_t shown = 0;
        for (const auto& item : items)
        {
            if (item.empty())
                continue;
            AddLine(out, "- " + item);
            ++shown;
            if (shown >= maxItems)
                break;
        }
        if (items.size() > shown)
            AddLine(out, "- ... and " + std::to_string(items.size() - shown) + " more");
    }

    void ReportProgress(const AnalysisProgressCallback& callback,
                        const std::string& mode,
                        const std::string& stage,
                        const std::string& detail,
                        std::uint64_t processed,
                        std::uint64_t total,
                        int percent,
                        std::uint64_t chunkIndex = 0,
                        std::uint64_t chunkCount = 0,
                        double speedMBps = 0.0,
                        int etaSeconds = -1,
                        bool heavyFileMode = false)
    {
        if (!callback)
            return;

        AnalysisProgress p;
        p.mode = mode;
        p.stage = stage;
        p.detail = detail;
        p.processedBytes = processed;
        p.totalBytes = total;
        p.chunkIndex = chunkIndex;
        p.chunkCount = chunkCount;
        p.speedMBps = speedMBps;
        p.etaSeconds = etaSeconds;
        p.percent = percent;
        p.heavyFileMode = heavyFileMode;
        p.cancellationRequested = IsAnalysisCancellationRequested();
        callback(p);
    }

    std::string DetectDisplayedType(const FileInfo& info)
    {
        std::string ext = info.extension;
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        if (info.isZipArchive || ext == ".zip" || ext == ".rar" || ext == ".7z" || ext == ".tar" || ext == ".gz")
            return "Archive";
        if (ext == ".msi")
            return "Windows installer package";
        if (info.isPELike)
        {
            if (ext == ".exe") return "Windows executable";
            if (ext == ".dll") return "Windows DLL";
            if (ext == ".sys") return "Windows driver";
            if (ext == ".ocx") return "ActiveX control";
            if (ext == ".scr") return "Screensaver executable";
            return "Portable Executable (PE)";
        }
        if (info.isScriptLike)
        {
            if (ext == ".ps1") return "PowerShell script";
            if (ext == ".js") return "JavaScript file";
            if (ext == ".vbs") return "VBScript file";
            if (ext == ".bat" || ext == ".cmd") return "Batch script";
            if (ext == ".hta") return "HTA application";
            return "Script-like";
        }
        if (ext == ".pdf") return "PDF document";
        if (ext == ".txt" || ext == ".log" || ext == ".md" || ext == ".ini" || ext == ".cfg") return "Text file";
        if (ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".bmp" || ext == ".gif") return "Image file";
        return "Generic file";
    }


    std::string BuildExecutiveRiskSummary(const std::string& targetType, int riskScore, const std::string& verdict, const std::vector<std::string>& topSignals, const std::vector<std::string>& legitimateContext)
    {
        std::string out;
        AddSection(out, "Executive Summary");
        AddLine(out, "Target Type: " + targetType);
        AddLine(out, "Risk Score: " + std::to_string(riskScore) + "%");
        AddLine(out, "Verdict: " + verdict);
        if (!topSignals.empty())
        {
            AddLine(out, "Top Signals:");
            AddTopList(out, topSignals, 4);
        }
        if (!legitimateContext.empty())
        {
            AddLine(out, "Legitimate Context:");
            AddTopList(out, legitimateContext, 3);
        }
        return out;
    }

    std::vector<std::string> BuildTopSignals(const std::vector<std::string>& reasons, const AdvancedAnalysisSummary* advanced = nullptr)
    {
        std::vector<std::string> out;
        for (const auto& reason : reasons)
        {
            if (!reason.empty())
                out.push_back(reason);
            if (out.size() >= 4)
                break;
        }
        if (advanced)
        {
            for (const auto& item : advanced->correlationHighlights)
            {
                if (out.size() >= 4)
                    break;
                out.push_back(item);
            }
        }
        return out;
    }

    std::string BuildIocExportText(const Indicators& indicators)
    {
        std::string out = "BinaryLens IOC Export\r\n\r\n";
        AddSection(out, "Network IOCs");
        if (!indicators.urls.empty()) { AddLine(out, "URLs:"); AddTopList(out, indicators.urls, indicators.urls.size()); }
        if (!indicators.domains.empty()) { AddLine(out, "Domains:"); AddTopList(out, indicators.domains, indicators.domains.size()); }
        if (!indicators.ips.empty()) { AddLine(out, "IPs:"); AddTopList(out, indicators.ips, indicators.ips.size()); }
        if (!indicators.emails.empty()) { AddLine(out, "Emails:"); AddTopList(out, indicators.emails, indicators.emails.size()); }
        AddSection(out, "Host / Execution Artifacts");
        if (!indicators.filePaths.empty()) { AddLine(out, "Paths:"); AddTopList(out, indicators.filePaths, indicators.filePaths.size()); }
        if (!indicators.registryKeys.empty()) { AddLine(out, "Registry Keys:"); AddTopList(out, indicators.registryKeys, indicators.registryKeys.size()); }
        // command tokens are useful, but they stay conservative until corroborated by other engines.
        if (!indicators.suspiciousCommands.empty()) { AddLine(out, "Commands:"); AddTopList(out, indicators.suspiciousCommands, indicators.suspiciousCommands.size()); }
        if (indicators.urls.empty() && indicators.domains.empty() && indicators.ips.empty() && indicators.emails.empty() && indicators.filePaths.empty() && indicators.registryKeys.empty() && indicators.suspiciousCommands.empty())
            AddLine(out, "- No high-confidence IOCs were extracted");
        return out;
    }

    struct CustomRule
    {
        std::string name;
        std::vector<std::string> tokens;
    };

    // custom rules are simple all-token matches so local tweaks stay easy to maintain.
    std::vector<CustomRule> LoadCustomRules()
    {
        std::vector<CustomRule> rules;
        const char* paths[] = {"BinaryLens_rules.txt", "binarylens_rules.txt"};
        for (const char* path : paths)
        {
            std::ifstream in(path);
            if (!in)
                continue;
            std::string line;
            while (std::getline(in, line))
            {
                if (line.empty() || line[0] == '#')
                    continue;
                std::vector<std::string> parts;
                std::stringstream ss(line);
                std::string item;
                while (std::getline(ss, item, '|'))
                {
                    item = ToLowerCopy(item);
                    if (!item.empty())
                        parts.push_back(item);
                }
                if (parts.size() >= 2)
                {
                    CustomRule rule;
                    rule.name = parts.front();
                    rule.tokens.assign(parts.begin() + 1, parts.end());
                    rules.push_back(rule);
                }
            }
            if (!rules.empty())
                break;
        }
        return rules;
    }

    void ApplyCustomRules(const std::vector<CustomRule>& rules, const std::string& searchableText, Indicators& indicators)
    {
        const std::string lower = ToLowerCopy(searchableText);
        for (const auto& rule : rules)
        {
            // require every token from the rule line so one broad term does not overmatch.
            bool matched = true;
            for (const auto& token : rule.tokens)
            {
                if (lower.find(token) == std::string::npos)
                {
                    matched = false;
                    break;
                }
            }
            if (matched)
                AddReasonIfMissing(indicators.matchedRules, "Custom rule matched: " + rule.name);
        }
    }
    std::string BuildUserViewText(const std::string& targetLine,
                                  int riskScore,
                                  const std::string& verdict,
                                  const std::vector<std::string>& reasons,
                                  const std::vector<std::string>& legitimateContext,
                                  const std::vector<std::string>& iocSummary,
                                  const std::vector<std::string>& yaraSummary = {},
                                  const std::vector<std::string>& simulatedBehaviors = {},
                                  const std::vector<std::string>& contextTags = {})
    {
        std::string out = "BinaryLens Scan Result\r\n\r\n";
        out += BuildExecutiveRiskSummary(targetLine, riskScore, verdict, BuildTopSignals(reasons), legitimateContext);
        AddSection(out, "What this means");
        if (riskScore >= 75)
            AddLine(out, "The file looks highly suspicious and deserves isolation plus deeper review.");
        else if (riskScore >= 45)
            AddLine(out, "The file has mixed signals. Review the technical findings before trusting it.");
        else
            AddLine(out, "The file looks lower risk based on current heuristics, but the result is not a guarantee of safety.");
        AddSection(out, "Why BinaryLens flagged it");
        out += BuildReasonsBlock(reasons);
        if (!yaraSummary.empty())
        {
            AddSection(out, "YARA Snapshot");
            AddTopList(out, yaraSummary, 4);
        }
        if (!simulatedBehaviors.empty())
        {
            AddSection(out, "Simulated Behavior");
            AddTopList(out, simulatedBehaviors, 4);
        }
        if (!contextTags.empty())
        {
            AddSection(out, "Context Reductions");
            AddTopList(out, contextTags, 4);
        }
        if (!legitimateContext.empty())
        {
            AddSection(out, "Why it may still be legitimate");
            AddTopList(out, legitimateContext, 4);
        }
        if (!iocSummary.empty())
        {
            AddSection(out, "IOC Snapshot");
            AddTopList(out, iocSummary, 6);
        }
        AddSection(out, "Next steps");
        AddLine(out, "- Verify the publisher, download source, and hash reputation");
        AddLine(out, "- Use Analyst View for detailed PE/import/IOC context");
        return out;
    }

}


AnalysisReportData RunUrlAnalysisDetailed(const std::string& inputURL)
{
    std::string result = "BinaryLens Scan Result\r\n\r\n";
    const std::string vtApiKey = LoadVTApiKey();
    const std::string normalizedURL = NormalizeURL(inputURL);
    const bool looksValid = LooksLikeURL(inputURL);
    const UrlAnalysis urlInfo = AnalyzeUrl(normalizedURL);
    // preflight keeps the url report grounded in the headers actually returned.
    const URLPreflightResult preflight = FetchURLPreflight((urlInfo.redirected && !urlInfo.finalUrl.empty()) ? urlInfo.finalUrl : normalizedURL);
    const std::string vtTargetUrl = (urlInfo.redirected && !urlInfo.finalUrl.empty()) ? urlInfo.finalUrl : normalizedURL;

    AddLine(result, "Target Type: URL / IP");
    AddLine(result, "Target: " + normalizedURL);

    AddSection(result, "URL Identity");
    AddLine(result, "Looks Valid: " + std::string(looksValid ? "Yes" : "No"));
    AddLine(result, "Normalized URL: " + (urlInfo.normalizedUrl.empty() ? normalizedURL : urlInfo.normalizedUrl));
    AddLine(result, "Scheme: " + (urlInfo.scheme.empty() ? std::string("[unknown]") : urlInfo.scheme));
    AddLine(result, "Host: " + (urlInfo.host.empty() ? std::string("[unavailable]") : urlInfo.host));
    AddLine(result, "Normalized Host: " + (urlInfo.normalizedHost.empty() ? std::string("[unavailable]") : urlInfo.normalizedHost));
    AddLine(result, "Domain: " + (urlInfo.rawIpUrl ? std::string("[none - raw ip target]") : (urlInfo.domain.empty() ? std::string("[unavailable]") : urlInfo.domain)));
    AddLine(result, "Subdomain: " + (urlInfo.rawIpUrl ? std::string("[none - raw ip target]") : (urlInfo.subdomain.empty() ? std::string("[none]") : urlInfo.subdomain)));
    AddLine(result, "Path: " + (urlInfo.path.empty() ? std::string("/") : urlInfo.path));
    AddLine(result, "Decoded Path / URL Traits: " + (urlInfo.decodedUrl.empty() ? std::string("[unavailable]") : urlInfo.decodedUrl.substr(0, std::min<std::size_t>(160, urlInfo.decodedUrl.size()))));
    AddLine(result, "Query String Present: " + std::string(urlInfo.hasQuery ? "Yes" : "No"));
    AddLine(result, "Query Parameters: " + std::to_string(urlInfo.queryParameterCount));
    AddLine(result, "Path Segments: " + std::to_string(urlInfo.pathSegmentCount));
    if (!urlInfo.port.empty())
        AddLine(result, "Port: " + urlInfo.port);
    AddLine(result, "Uses HTTPS: " + std::string(urlInfo.https ? "Yes" : "No"));

    AddSection(result, "URL Classification");
    AddLine(result, "Category: " + (urlInfo.urlCategory.empty() ? std::string("[unclassified]") : urlInfo.urlCategory));
    AddLine(result, "Domain Trust: " + (urlInfo.domainTrustLabel.empty() ? std::string("[unclassified]") : urlInfo.domainTrustLabel));
    AddLine(result, "Likely File Name: " + (urlInfo.likelyFileName.empty() ? std::string("[none]") : urlInfo.likelyFileName));
    AddLine(result, "Likely Payload Type: " + (urlInfo.likelyPayloadType.empty() ? std::string("[none]") : urlInfo.likelyPayloadType));
    AddLine(result, "Brand Impersonation: " + std::string(urlInfo.likelyBrandImpersonation ? "Yes" : "No"));
    if (!urlInfo.impersonatedBrand.empty())
        AddLine(result, "Impersonated Brand Hint: " + urlInfo.impersonatedBrand);

    AddSection(result, "DNS / Network Resolution");
    AddLine(result, "Resolved IP: " + (urlInfo.resolvedIp.empty() ? std::string("[unavailable]") : urlInfo.resolvedIp));
    AddLine(result, "IP Version: " + (urlInfo.ipVersion.empty() ? std::string("[unavailable]") : urlInfo.ipVersion));
    AddLine(result, "Reverse DNS: " + (urlInfo.reverseDns.empty() ? std::string("[none]") : urlInfo.reverseDns));
    AddLine(result, "Raw IP URL: " + std::string(urlInfo.rawIpUrl ? "Yes" : "No"));
    AddLine(result, "Private IP: " + std::string(urlInfo.isPrivateIp ? "Yes" : "No"));
    AddLine(result, "Loopback IP: " + std::string(urlInfo.isLoopbackIp ? "Yes" : "No"));
    AddLine(result, "Link-Local IP: " + std::string(urlInfo.isLinkLocalIp ? "Yes" : "No"));
    AddLine(result, "Carrier-Grade NAT IP: " + std::string(urlInfo.isCarrierGradeNatIp ? "Yes" : "No"));
    AddLine(result, "Documentation/Test IP: " + std::string(urlInfo.isDocumentationIp ? "Yes" : "No"));
    AddLine(result, "Reserved / Special Range: " + std::string(urlInfo.isReservedIp ? "Yes" : "No"));
    AddLine(result, "DNS Resolution Failed: " + std::string(urlInfo.dnsResolutionFailed ? "Yes" : "No"));
    AddLine(result, "Local / Lab Hostname: " + std::string(urlInfo.localNetworkHost ? "Yes" : "No"));
    AddLine(result, "Exclusive IP: " + std::string(urlInfo.likelyExclusiveIp ? "Possible" : (urlInfo.likelySharedHosting ? "Likely Shared" : "Unknown")));

    AddSection(result, "Infrastructure");
    AddLine(result, "Provider: " + (urlInfo.provider.empty() ? std::string("[unavailable]") : urlInfo.provider));
    AddLine(result, "Organization: " + (urlInfo.organization.empty() ? std::string("[unavailable]") : urlInfo.organization));
    AddLine(result, "ASN: " + ((urlInfo.asn.empty() && urlInfo.asName.empty()) ? std::string("[unavailable]") : (urlInfo.asn + (urlInfo.asName.empty() ? std::string() : (" " + urlInfo.asName)))));
    AddLine(result, "Ownership Summary: " + (urlInfo.ownershipSummary.empty() ? std::string("[unavailable]") : urlInfo.ownershipSummary));
    AddLine(result, "Infrastructure Class: " + (urlInfo.infrastructureClass.empty() ? std::string("[unavailable]") : urlInfo.infrastructureClass));
    AddLine(result, "Exposure Scope: " + (urlInfo.exposureLabel.empty() ? std::string("[unavailable]") : urlInfo.exposureLabel));
    AddLine(result, "Likely Service Purpose: " + (urlInfo.likelyServicePurpose.empty() ? std::string("[unavailable]") : urlInfo.likelyServicePurpose));
    AddLine(result, "Hosting Type: " + (urlInfo.hostingType.empty() ? std::string("[unavailable]") : urlInfo.hostingType));
    AddLine(result, "Cloud / CDN Infrastructure: " + std::string(urlInfo.cloudOrCdnInfrastructure ? "Likely Yes" : "Not observed"));
    AddLine(result, "Dynamic DNS Style Host: " + std::string(urlInfo.likelyDynamicDns ? "Yes" : "No"));

    AddSection(result, "Geographic Information");
    AddLine(result, "Country: " + (urlInfo.country.empty() ? std::string("[unavailable]") : urlInfo.country));
    AddLine(result, "Region: " + (urlInfo.region.empty() ? std::string("[unavailable]") : urlInfo.region));
    AddLine(result, "City: " + (urlInfo.city.empty() ? std::string("[unavailable]") : urlInfo.city));

    AddSection(result, "Redirect / Delivery Behavior");
    AddLine(result, "Redirected: " + std::string(urlInfo.redirected ? "Yes" : "No"));
    AddLine(result, "Redirect Count: " + std::to_string(urlInfo.redirectCount));
    AddLine(result, "Final URL: " + (urlInfo.finalUrl.empty() ? normalizedURL : urlInfo.finalUrl));
    AddLine(result, "Cross-Host Redirect: " + std::string(urlInfo.redirectsCrossHost ? "Yes" : "No"));
    AddLine(result, "Known File-Share / Paste Provider: " + std::string(urlInfo.knownFileShareProvider ? "Yes" : "No"));
    AddLine(result, "Direct File Link: " + std::string(urlInfo.directFileLink ? "Yes" : "No"));
    AddLine(result, "Credential Harvest Likely: " + std::string(urlInfo.likelyCredentialHarvest ? "Yes" : "No"));
    AddLine(result, "Payload Delivery Likely: " + std::string(urlInfo.likelyPayloadDelivery ? "Yes" : "No"));

    AddSection(result, "HTTP Preflight");
    AddLine(result, "Preflight Success: " + std::string(preflight.success ? "Yes" : "No"));
    if (preflight.httpStatusCode > 0)
        AddLine(result, "HTTP Status: " + std::to_string(preflight.httpStatusCode));
    AddLine(result, "Content Type: " + (preflight.contentType.empty() ? std::string("[unavailable]") : preflight.contentType));
    AddLine(result, "Server Header: " + (preflight.serverHeader.empty() ? std::string("[unavailable]") : preflight.serverHeader));
    AddLine(result, "Suggested File Name: " + (preflight.suggestedFileName.empty() ? std::string("[none]") : preflight.suggestedFileName));
    if (preflight.contentLength > 0)
        AddLine(result, "Content Length: " + std::to_string(preflight.contentLength) + " bytes");
    AddLine(result, "Likely HTML: " + std::string(preflight.likelyHtml ? "Yes" : "No"));
    AddLine(result, "Likely Download: " + std::string(preflight.likelyDownload ? "Yes" : "No"));
    AddLine(result, "Likely Executable: " + std::string(preflight.likelyExecutable ? "Yes" : "No"));
    AddLine(result, "Likely Archive: " + std::string(preflight.likelyArchive ? "Yes" : "No"));
    AddLine(result, "Likely Script: " + std::string(preflight.likelyScript ? "Yes" : "No"));

    AddSection(result, "Security Signals");
    if (!urlInfo.securitySignals.empty())
        AddTopList(result, urlInfo.securitySignals, 10);
    else
        AddLine(result, "- No strong URL or IP abuse signals were detected");

    AddSection(result, "Behavior Simulation");
    if (!urlInfo.behaviorHints.empty())
        AddTopList(result, urlInfo.behaviorHints, 8);
    else
        AddLine(result, "- No strong behavioral narrative was inferred from the URL structure");

    AddSection(result, "Domain Context");
    if (!urlInfo.domainContextTags.empty())
    {
        std::vector<std::string> humanizedContext;
        for (const auto& tag : urlInfo.domainContextTags)
            humanizedContext.push_back(HumanizeDomainContextTag(tag));
        AddTopList(result, humanizedContext, 8);
    }
    else
        AddLine(result, "- No special domain context tags were derived");

    AddSection(result, "Reputation");
    URLReputationResult rep;
    ReputationResult ipRep;
    if (looksValid && !vtApiKey.empty() && vtApiKey.rfind("DEBUG_ERR_", 0) != 0)
    {
        if (urlInfo.rawIpUrl && !urlInfo.resolvedIp.empty())
        {
            ipRep = QueryVirusTotalIp(urlInfo.resolvedIp, vtApiKey);
            if (ipRep.httpStatusCode == 200 && ipRep.success)
            {
                AddLine(result, "VirusTotal IP Malicious: " + std::to_string(ipRep.maliciousDetections));
                AddLine(result, "VirusTotal IP Suspicious: " + std::to_string(ipRep.suspiciousDetections));
                AddLine(result, "VirusTotal IP Harmless: " + std::to_string(ipRep.harmlessDetections));
                AddLine(result, "VirusTotal IP Undetected: " + std::to_string(ipRep.undetectedDetections));
            }
            else
            {
                AddLine(result, "VirusTotal IP: " + ipRep.summary);
            }
        }
        else
        {
            rep = QueryVirusTotalURL(vtTargetUrl, vtApiKey);
            if (rep.httpStatusCode == 200 && rep.success)
            {
                AddLine(result, "VirusTotal Malicious: " + std::to_string(rep.maliciousDetections));
                AddLine(result, "VirusTotal Suspicious: " + std::to_string(rep.suspiciousDetections));
                AddLine(result, "VirusTotal Harmless: " + std::to_string(rep.harmlessDetections));
                AddLine(result, "VirusTotal Undetected: " + std::to_string(rep.undetectedDetections));
            }
            else
            {
                AddLine(result, "VirusTotal: " + rep.summary);
            }
        }
    }
    else
    {
        AddLine(result, urlInfo.rawIpUrl ? "VirusTotal IP reputation not queried" : "VirusTotal: URL reputation not queried");
    }

    RiskAccumulator urlRisk;
    if (!looksValid)
        urlRisk.Add(35, "Input does not appear to be a valid URL or routable IP target");
    if (urlInfo.usesShortener)
        urlRisk.Add(18, "URL uses a shortening service");
    if (urlInfo.isIp)
        urlRisk.Add(urlInfo.isPrivateIp ? 5 : 16, "URL uses a direct IP address instead of a domain");
    if (urlInfo.suspiciousTld)
        urlRisk.Add(14, "Suspicious top-level domain detected");
    if (urlInfo.punycode)
        urlRisk.Add(22, "Punycode detected (possible homograph attack)");
    if (urlInfo.suspiciousQuery || urlInfo.suspiciousEncodedSegments || urlInfo.doubleEncoded)
        urlRisk.Add(14, "Obfuscated or suspicious query / encoding pattern detected");
    if (urlInfo.longQueryBlob)
        urlRisk.Add(10, "Large encoded or token-heavy query blob detected");
    if (urlInfo.loginBrandLure || urlInfo.likelyBrandImpersonation)
        urlRisk.Add(20, "Brand impersonation or credential lure pattern detected");
    if (urlInfo.likelyCredentialHarvest)
        urlRisk.Add(20, "URL structure suggests credential collection");
    if (urlInfo.likelyDynamicDns)
        urlRisk.Add(12, "Dynamic DNS style infrastructure detected");
    if (urlInfo.isPrivateIp)
        urlRisk.Add(6, "Private IP target detected; verify that the target is intentionally internal");
    if (urlInfo.isLoopbackIp || urlInfo.localNetworkHost)
        urlRisk.Add(-8, "Loopback or local-lab destination reduces public internet threat certainty");
    if (urlInfo.isLinkLocalIp || urlInfo.isCarrierGradeNatIp)
        urlRisk.Add(4, "Special-use network range detected; validate the routing context");
    if (urlInfo.isDocumentationIp)
        urlRisk.Add(-12, "Documentation/test IP range strongly suggests a non-live target");
    if (urlInfo.isReservedIp && !urlInfo.isDocumentationIp && !urlInfo.isLinkLocalIp && !urlInfo.isCarrierGradeNatIp)
        urlRisk.Add(8, "Reserved or special-use IP range detected");
    if (urlInfo.redirected && urlInfo.redirectCount >= 2)
        urlRisk.Add(10, "Multiple URL redirects were observed");
    if (urlInfo.redirectsCrossHost)
        urlRisk.Add(12, "Redirect chain changes the effective host");
    if (urlInfo.dnsResolutionFailed)
        urlRisk.Add(10, "DNS resolution failed for the final host");
    if (!urlInfo.https)
        urlRisk.Add(6, "Target does not use HTTPS");
    if (urlInfo.suspiciousPort)
        urlRisk.Add(12, "Uncommon service port detected");
    if (urlInfo.hasUserInfo)
        urlRisk.Add(18, "User-info or '@' based authority confusion detected");
    if (urlInfo.directFileLink)
        urlRisk.Add(urlInfo.likelyExecutableDownload ? 22 : 12, "URL appears to directly deliver a file payload");
    if (urlInfo.knownFileShareProvider && urlInfo.directFileLink)
        urlRisk.Add(8, "Payload delivery is staged through a file-sharing or paste-style provider");
    if (preflight.likelyExecutable)
        urlRisk.Add(20, "HTTP preflight suggests executable or binary payload delivery");
    if (preflight.likelyArchive || preflight.likelyScript)
        urlRisk.Add(12, "HTTP preflight suggests archive or script delivery");
    if (preflight.likelyHtml && urlInfo.likelyCredentialHarvest)
        urlRisk.Add(10, "Landing page characteristics align with potential phishing flow");
    if (rep.httpStatusCode == 200 && rep.success)
    {
        if (rep.maliciousDetections > 0)
            urlRisk.Add(35, "VirusTotal detected the URL as malicious");
        else if (rep.suspiciousDetections > 0)
            urlRisk.Add(18, "VirusTotal detected the URL as suspicious");
        else
            urlRisk.Add(-10, "No detections from VirusTotal engines");
    }
    if (ipRep.httpStatusCode == 200 && ipRep.success)
    {
        if (ipRep.maliciousDetections > 0)
            urlRisk.Add(24, "VirusTotal detected the target IP as malicious");
        else if (ipRep.suspiciousDetections > 0)
            urlRisk.Add(12, "VirusTotal marked the target IP as suspicious");
        else
            urlRisk.Add(-6, "No detections from VirusTotal IP reputation engines");
    }
    if ((urlInfo.knownSafeDomain || urlInfo.knownSafeProvider) && !urlInfo.likelyBrandImpersonation && !urlInfo.usesShortener)
        urlRisk.Add(-8, "Trusted domain or provider context slightly reduces risk");
    if (urlInfo.rawIpUrl && !urlInfo.organization.empty() && !urlInfo.likelyDynamicDns && !urlInfo.directFileLink)
        urlRisk.Add(-4, "Identified provider ownership reduces uncertainty for the raw IP target");
    if (urlInfo.cloudOrCdnInfrastructure && !urlInfo.directFileLink)
        urlRisk.Add(-3, "Shared CDN or cloud edge infrastructure reduces certainty");
    if ((urlInfo.isPrivateIp || urlInfo.isLoopbackIp || urlInfo.localNetworkHost) && !urlInfo.directFileLink)
        urlRisk.Add(-6, "Internal or local-scope targeting is less consistent with public internet abuse");

    urlRisk.Clamp();
    const int urlRiskScore = urlRisk.Score();
    const std::vector<std::string> urlReasons = urlRisk.Reasons();

    AddSection(result, "Final Assessment");
    AddLine(result, "Risk Score: " + std::to_string(urlRiskScore) + "%");
    AddLine(result, "Verdict: " + VerdictLabelFromScore(urlRiskScore));
    AddSection(result, "Reasons");
    result += BuildReasonsBlock(urlReasons);
    AddSection(result, "Notice");
    AddLine(result, "This analysis is heuristic-based and there are real chances of false positives or false negatives.");
    AddLine(result, "Status: Analysis complete");

    nlohmann::json jsonReport;
    jsonReport["target_type"] = "url_or_ip";
    jsonReport["target"] = normalizedURL;
    jsonReport["looks_valid"] = looksValid;
    jsonReport["normalized_url"] = urlInfo.normalizedUrl.empty() ? normalizedURL : urlInfo.normalizedUrl;
    jsonReport["decoded_url"] = urlInfo.decodedUrl;
    jsonReport["scheme"] = urlInfo.scheme;
    jsonReport["host"] = urlInfo.host;
    jsonReport["normalized_host"] = urlInfo.normalizedHost;
    jsonReport["domain"] = urlInfo.domain;
    jsonReport["subdomain"] = urlInfo.subdomain;
    jsonReport["path"] = urlInfo.path;
    jsonReport["path_segments"] = urlInfo.pathSegmentCount;
    jsonReport["query_parameter_count"] = urlInfo.queryParameterCount;
    jsonReport["has_query"] = urlInfo.hasQuery;
    jsonReport["port"] = urlInfo.port;
    jsonReport["uses_https"] = urlInfo.https;
    jsonReport["resolved_ip"] = urlInfo.resolvedIp;
    jsonReport["ip_version"] = urlInfo.ipVersion;
    jsonReport["reverse_dns"] = urlInfo.reverseDns;
    jsonReport["raw_ip_url"] = urlInfo.rawIpUrl;
    jsonReport["is_private_ip"] = urlInfo.isPrivateIp;
    jsonReport["is_reserved_ip"] = urlInfo.isReservedIp;
    jsonReport["is_loopback_ip"] = urlInfo.isLoopbackIp;
    jsonReport["is_link_local_ip"] = urlInfo.isLinkLocalIp;
    jsonReport["is_carrier_grade_nat_ip"] = urlInfo.isCarrierGradeNatIp;
    jsonReport["is_documentation_ip"] = urlInfo.isDocumentationIp;
    jsonReport["dns_resolution_failed"] = urlInfo.dnsResolutionFailed;
    jsonReport["local_network_host"] = urlInfo.localNetworkHost;
    jsonReport["likely_exclusive_ip"] = urlInfo.likelyExclusiveIp;
    jsonReport["likely_shared_hosting"] = urlInfo.likelySharedHosting;
    jsonReport["provider"] = urlInfo.provider;
    jsonReport["organization"] = urlInfo.organization;
    jsonReport["asn"] = urlInfo.asn;
    jsonReport["as_name"] = urlInfo.asName;
    jsonReport["ownership_summary"] = urlInfo.ownershipSummary;
    jsonReport["infrastructure_class"] = urlInfo.infrastructureClass;
    jsonReport["exposure_scope"] = urlInfo.exposureLabel;
    jsonReport["likely_service_purpose"] = urlInfo.likelyServicePurpose;
    jsonReport["hosting_type"] = urlInfo.hostingType;
    jsonReport["cloud_or_cdn_infrastructure"] = urlInfo.cloudOrCdnInfrastructure;
    jsonReport["known_safe_provider"] = urlInfo.knownSafeProvider;
    jsonReport["known_safe_domain"] = urlInfo.knownSafeDomain;
    jsonReport["known_file_share_provider"] = urlInfo.knownFileShareProvider;
    jsonReport["country"] = urlInfo.country;
    jsonReport["region"] = urlInfo.region;
    jsonReport["city"] = urlInfo.city;
    jsonReport["redirected"] = urlInfo.redirected;
    jsonReport["redirect_count"] = urlInfo.redirectCount;
    jsonReport["redirects_cross_host"] = urlInfo.redirectsCrossHost;
    jsonReport["final_url"] = urlInfo.finalUrl.empty() ? normalizedURL : urlInfo.finalUrl;
    jsonReport["url_category"] = urlInfo.urlCategory;
    jsonReport["domain_trust_label"] = urlInfo.domainTrustLabel;
    jsonReport["likely_file_name"] = urlInfo.likelyFileName;
    jsonReport["likely_payload_type"] = urlInfo.likelyPayloadType;
    jsonReport["direct_file_link"] = urlInfo.directFileLink;
    jsonReport["likely_credential_harvest"] = urlInfo.likelyCredentialHarvest;
    jsonReport["likely_payload_delivery"] = urlInfo.likelyPayloadDelivery;
    jsonReport["likely_brand_impersonation"] = urlInfo.likelyBrandImpersonation;
    jsonReport["impersonated_brand"] = urlInfo.impersonatedBrand;
    jsonReport["security_signals"] = urlInfo.securitySignals;
    jsonReport["domain_context_tags"] = urlInfo.domainContextTags;
    jsonReport["behavior_hints"] = urlInfo.behaviorHints;
    jsonReport["preflight"] = {
        {"success", preflight.success},
        {"http_status_code", preflight.httpStatusCode},
        {"content_type", preflight.contentType},
        {"content_disposition", preflight.contentDisposition},
        {"server", preflight.serverHeader},
        {"suggested_file_name", preflight.suggestedFileName},
        {"content_length", preflight.contentLength},
        {"followed_redirect", preflight.followedRedirect},
        {"final_url", preflight.finalUrl},
        {"likely_html", preflight.likelyHtml},
        {"likely_download", preflight.likelyDownload},
        {"likely_script", preflight.likelyScript},
        {"likely_archive", preflight.likelyArchive},
        {"likely_executable", preflight.likelyExecutable},
        {"summary", preflight.summary}
    };
    jsonReport["risk_score"] = urlRiskScore;
    jsonReport["verdict"] = VerdictLabelFromScore(urlRiskScore);
    jsonReport["reasons"] = urlReasons;
    jsonReport["virustotal"] = {
        {"queried", looksValid && !vtApiKey.empty() && vtApiKey.rfind("DEBUG_ERR_", 0) != 0},
        {"mode", urlInfo.rawIpUrl ? "ip" : "url"},
        {"http_status_code", urlInfo.rawIpUrl ? ipRep.httpStatusCode : rep.httpStatusCode},
        {"success", urlInfo.rawIpUrl ? ipRep.success : rep.success},
        {"summary", urlInfo.rawIpUrl ? ipRep.summary : rep.summary},
        {"malicious", urlInfo.rawIpUrl ? ipRep.maliciousDetections : rep.maliciousDetections},
        {"suspicious", urlInfo.rawIpUrl ? ipRep.suspiciousDetections : rep.suspiciousDetections},
        {"harmless", urlInfo.rawIpUrl ? ipRep.harmlessDetections : rep.harmlessDetections},
        {"undetected", urlInfo.rawIpUrl ? ipRep.undetectedDetections : rep.undetectedDetections}
    };

    std::vector<std::string> urlIocSummary;
    if (!urlInfo.host.empty()) urlIocSummary.push_back("Host: " + urlInfo.host);
    if (!urlInfo.resolvedIp.empty()) urlIocSummary.push_back("Resolved IP: " + urlInfo.resolvedIp);
    if (!urlInfo.urlCategory.empty()) urlIocSummary.push_back("Category: " + urlInfo.urlCategory);
    if (!urlInfo.likelyPayloadType.empty()) urlIocSummary.push_back("Payload: " + urlInfo.likelyPayloadType);
    for (const auto& sig : urlInfo.securitySignals)
    {
        if (urlIocSummary.size() >= 8)
            break;
        urlIocSummary.push_back(sig);
    }

    const std::string userView = BuildUserViewText("URL / IP", urlRiskScore, VerdictLabelFromScore(urlRiskScore), urlReasons, {}, urlIocSummary);
    return { userView, result, std::string(), jsonReport.dump(2) };
}


// network-focused entry path that skips file engines and renders a url-centered report.
std::string RunUrlAnalysis(const std::string& inputURL)
{
    return RunUrlAnalysisDetailed(inputURL).textReport;
}

// coordinates the full file workflow, schedules parallel engines, and assembles the final report payload.
AnalysisReportData RunFileAnalysisDetailed(const std::string& filePath, AnalysisProgressCallback progressCallback)
{
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    std::uint64_t fileSize = 0;
    if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fad))
    {
        ULARGE_INTEGER ul = {};
        ul.HighPart = fad.nFileSizeHigh;
        ul.LowPart = fad.nFileSizeLow;
        fileSize = ul.QuadPart;
    }

    const bool heavyMode = fileSize >= kHeavyFileThreshold;
    const std::string modeLabel = heavyMode ? "Heavy File Analysis" : "Standard File Analysis";

    ReportProgress(progressCallback,
                   modeLabel,
                   "Initializing analysis",
                   heavyMode ? "Heavy File Mode active (512 MB+). Preparing detailed streamed analysis." : "Preparing standard streamed analysis.",
                   0,
                   fileSize,
                   1);

    const auto startTime = GetTickCount64();

    // the file scan owns progress up to roughly 60 percent because it handles the streamed heavy work.
    FileInfo info = AnalyzeFile(filePath, [&](const std::string& stage,
                                              const std::string& detail,
                                              std::uint64_t processed,
                                              std::uint64_t total,
                                              std::uint64_t chunkIndex,
                                              std::uint64_t chunkCount)
    {
        int percent = 5;
        if (total > 0)
        {
            const double ratio = static_cast<double>(processed) / static_cast<double>(total);
            percent = 5 + static_cast<int>(ratio * 55.0);
        }
        if (percent > 60)
            percent = 60;

        const ULONGLONG elapsedMs = GetTickCount64() - startTime;
        const double elapsedSeconds = elapsedMs > 0 ? static_cast<double>(elapsedMs) / 1000.0 : 0.0;
        const double speedMBps = elapsedSeconds > 0.0 ? (static_cast<double>(processed) / (1024.0 * 1024.0)) / elapsedSeconds : 0.0;
        int etaSeconds = -1;
        if (speedMBps > 0.0 && total > processed)
        {
            const double remainingMB = static_cast<double>(total - processed) / (1024.0 * 1024.0);
            etaSeconds = static_cast<int>(remainingMB / speedMBps);
        }

        ReportProgress(progressCallback, modeLabel, stage, detail, processed, total, percent, chunkIndex, chunkCount, speedMBps, etaSeconds, heavyMode);
    });

    if (info.cancelled)
    {
        std::string cancelled = "BinaryLens Scan Result\r\n\r\n";
        AddLine(cancelled, "Target Type: File");
        AddLine(cancelled, "Target: " + filePath);
        AddSection(cancelled, "Status");
        AddLine(cancelled, "Analysis was cancelled by the user.");
        AddLine(cancelled, "Processed Bytes: " + FormatFileSize(info.size > 0 ? info.size : 0));
        AddSection(cancelled, "Notice");
        AddLine(cancelled, "This analysis is heuristic-based and there are real chances of false positives or false negatives.");
        ReportProgress(progressCallback, modeLabel, "Cancelled", "Analysis cancelled by user", info.size, info.size, 100, 0, 0, 0.0, 0, heavyMode);
        return { cancelled, cancelled, std::string(), std::string() };
    }

    AnalysisReportData cachedReport;
    if (TryLoadAnalysisCache(info, cachedReport))
    {
        ReportProgress(progressCallback, modeLabel, "Cache hit", "Loaded prior analysis cache for this sha-256", info.size, info.size, 100, 0, 0, 0.0, 0, heavyMode);
        return cachedReport;
    }

    // launch the expensive engines early so the ui can keep moving while dependencies are still simple.
    PEAnalysisResult peInfo;
    SignatureCheckResult sigInfo;
    ImportAnalysisResult importInfo;
    Indicators indicators;
    ScriptAbuseAnalysisResult scriptAbuseInfo;
    EmbeddedPayloadAnalysisResult embeddedPayloadInfo;
    const bool shouldAnalyzePE = info.isPELike;
    const bool shouldCheckSignatureInfo = ShouldCheckSignature(info.extension);
    const std::string vtApiKey = LoadVTApiKey();
    const SchedulerProfile schedulerProfile = DetectSchedulerProfile();
    const unsigned int pipelineWorkers = ChoosePipelineWorkerCount(schedulerProfile, heavyMode);
    const bool allowParallel = schedulerProfile.parallelEnabled && pipelineWorkers > 1;
    AdaptiveTaskScheduler scheduler(pipelineWorkers);

    double peTaskMs = 0.0;
    double signatureTaskMs = 0.0;
    double importTaskMs = 0.0;
    double scriptTaskMs = 0.0;
    double embeddedPayloadTaskMs = 0.0;
    double indicatorTaskMs = 0.0;
    double yaraTaskMs = 0.0;
    double deobTaskMs = 0.0;
    double iocTaskMs = 0.0;
    double pluginTaskMs = 0.0;
    double memoryTaskMs = 0.0;
    double mlTaskMs = 0.0;
    double reputationTaskMs = 0.0;

    // pe, signature, import, string, and payload passes are scheduled independently when possible.
    auto peFuture = shouldAnalyzePE ? scheduler.Submit([filePath]() {
        return MeasureTaskMs([&]() { return AnalyzePEFile(filePath); });
    }) : std::future<std::pair<PEAnalysisResult, double>>{};
    auto sigFuture = shouldCheckSignatureInfo ? scheduler.Submit([filePath]() {
        return MeasureTaskMs([&]() { return CheckFileSignature(filePath); });
    }) : std::future<std::pair<SignatureCheckResult, double>>{};
    auto importFuture = shouldAnalyzePE ? scheduler.Submit([filePath]() {
        return MeasureTaskMs([&]() { return AnalyzePEImports(filePath); });
    }) : std::future<std::pair<ImportAnalysisResult, double>>{};
    auto scriptFuture = scheduler.Submit([&info]() {
        return MeasureTaskMs([&]() { return AnalyzeScriptAbuseContent(info); });
    });
    auto embeddedPayloadFuture = scheduler.Submit([filePath, &info]() {
        return MeasureTaskMs([&]() { return AnalyzeEmbeddedPayloads(filePath, info); });
    });
    auto indicatorFuture = scheduler.Submit([filePath, &info]() {
        return MeasureTaskMs([&]() {
            return !info.cachedPrintableText.empty() ? ExtractIndicatorsFromText(info.cachedPrintableText) : ExtractIndicators(filePath);
        });
    });

    ReportProgress(progressCallback, modeLabel, "Determining displayed file type", "Mapping extension and file header to user-facing type labels", info.size, info.size, 62);
    // compare the friendly type label against magic-byte reality before scoring deeper traits.
    const std::string detectedType = DetectDisplayedType(info);
    const std::vector<unsigned char> headerData = ReadFileHeaderBytes(info.path, 512);
    const std::string realType = DetectRealFileType(headerData);

    RiskAccumulator risk;
    risk.Seed(info.riskScore, info.reasons);

    const bool hasRealType = realType != "Unknown / generic";
    const bool typeMismatch = hasRealType &&
        ((detectedType == "Image file" && realType == "Portable Executable (PE)") ||
         (detectedType == "Text file" && realType == "Portable Executable (PE)") ||
         (detectedType == "PDF document" && realType == "Portable Executable (PE)") ||
         (detectedType == "Archive" && realType == "Portable Executable (PE)") ||
         (detectedType == "Windows executable" && realType != "Portable Executable (PE)") ||
         (detectedType == "Windows DLL" && realType != "Portable Executable (PE)"));

    // mismatched extension and header is one of the clearest first-pass deception signals.
    if (typeMismatch)
    {
        risk.Add(25, "File extension does not match detected file header");
    }

    if (shouldAnalyzePE)
    {
        ReportProgress(progressCallback, modeLabel, "Inspecting PE structure", "Parsing PE headers, sections, overlay, TLS callbacks, and entry point information", info.size, info.size, 68);
        auto pePair = peFuture.get();
        peInfo = std::move(pePair.first);
        peTaskMs = pePair.second;
    }

    if (shouldCheckSignatureInfo)
    {
        ReportProgress(progressCallback, modeLabel, "Verifying digital signature", "Checking Authenticode presence, signature validity, and publisher metadata", info.size, info.size, 74);
        auto sigPair = sigFuture.get();
        sigInfo = std::move(sigPair.first);
        signatureTaskMs = sigPair.second;
    }

    if (shouldAnalyzePE)
    {
        ReportProgress(progressCallback, modeLabel, "Analyzing imported APIs", "Inspecting import table for injection, evasion, network, and execution patterns", info.size, info.size, 80);
        auto importPair = importFuture.get();
        importInfo = std::move(importPair.first);
        importTaskMs = importPair.second;
    }

    ReportProgress(progressCallback, modeLabel, "Inspecting script abuse patterns", "Evaluating sampled text for script execution, download, persistence, and evasion traits", info.size, info.size, 82);
    auto scriptPair = scriptFuture.get();
    scriptAbuseInfo = std::move(scriptPair.first);
    scriptTaskMs = scriptPair.second;

    ReportProgress(progressCallback, modeLabel, "Scanning for embedded payloads", "Looking for embedded PE headers, shellcode-like blobs, and staged delivery traits", info.size, info.size, 83);
    auto embeddedPair = embeddedPayloadFuture.get();
    embeddedPayloadInfo = std::move(embeddedPair.first);
    embeddedPayloadTaskMs = embeddedPair.second;

    const bool trustedPublisher = IsTrustedPublisher(sigInfo);
    const bool trustedSignedArtifact = trustedPublisher && sigInfo.isSigned && sigInfo.signatureValid;

    bool scoredInjection = false;
    bool scoredDownloader = false;
    bool scoredEvasion = false;
    bool scoredRansomware = false;
    bool scoredCredential = false;
    bool scoredPersistence = false;
    bool scoredSpyware = false;

    if (shouldCheckSignatureInfo)
    {
        if (sigInfo.isSigned && sigInfo.signatureValid)
        {
            risk.Add(-(trustedPublisher ? 28 : 14), trustedPublisher ? "Valid digital signature from a known publisher detected" : "Valid digital signature detected");
        }
        else if (!sigInfo.isSigned)
        {
            risk.Add((info.extension == ".dll" ? 2 : 5), "Executable is not digitally signed");
        }
        else if (sigInfo.isSigned && !sigInfo.signatureValid)
        {
            risk.Add(20, "Digital signature validation failed");
        }
    }

    // script-like content inside non-script files is informative, but damped for trusted signed pe files.
    if (scriptAbuseInfo.likelyScriptContent)
    {
        const int scriptContentRisk = (trustedSignedArtifact && shouldAnalyzePE) ? 1 : 4;
        risk.Add(scriptContentRisk, "Script-capable content detected from sampled file text");
    }
    if (scriptAbuseInfo.hasDownloadCradle)
        risk.Add(14, "Script download cradle behavior detected");
    if (scriptAbuseInfo.hasEncodedPayload)
        risk.Add(12, "Encoded or transformed script payload traits detected");
    if (scriptAbuseInfo.hasExecutionAbuse)
        risk.Add(12, "Interpreter or LOLBin execution behavior detected in script content");
    if (scriptAbuseInfo.hasPersistenceAbuse)
        risk.Add(10, "Script persistence behavior detected");
    if (scriptAbuseInfo.hasObfuscationTraits)
        risk.Add(10, "Script evasion or stealth traits detected");

    if (embeddedPayloadInfo.foundEmbeddedPE)
    {
        const int embeddedPeRisk = embeddedPayloadInfo.validatedEmbeddedPE ? 20 : 10;
        risk.Add(embeddedPeRisk, embeddedPayloadInfo.validatedEmbeddedPE
            ? "Structurally valid embedded PE header detected inside the scanned file"
            : "Embedded PE-like marker detected inside the scanned file");
    }
    if (embeddedPayloadInfo.foundShellcodeLikeBlob)
    {
        const bool lowConfidenceBlob = (!embeddedPayloadInfo.foundEmbeddedPE && embeddedPayloadInfo.score <= 20) ||
                                       embeddedPayloadInfo.signalReliability == "Low" ||
                                       embeddedPayloadInfo.likelyCompressedNoise;
        const int shellcodeBlobRisk = lowConfidenceBlob
            ? ScaleAmbiguousExecutionRisk(7, trustedSignedArtifact, trustedPublisher, false, false)
            : (embeddedPayloadInfo.strongCorroboration ? 20 : 16);
        risk.Add(shellcodeBlobRisk, embeddedPayloadInfo.likelyCompressedNoise
            ? "Shellcode-like raw code region detected, but compressed-container characteristics lowered confidence"
            : "Shellcode-like raw code region detected");
    }
    if (embeddedPayloadInfo.foundExecutableArchiveLure)
        risk.Add(8, "Executable delivery lure pattern detected");
    if (!embeddedPayloadInfo.foundShellcodeLikeBlob && embeddedPayloadInfo.suspiciousWindowCount >= 3)
    {
        const int clusteredWindowRisk = embeddedPayloadInfo.likelyCompressedNoise ? 2 : 6;
        risk.Add(ScaleAmbiguousExecutionRisk(clusteredWindowRisk, trustedSignedArtifact, trustedPublisher, false, false),
                 embeddedPayloadInfo.likelyCompressedNoise
                    ? "Multiple suspicious raw code windows detected, but the region also looks compression-heavy"
                    : "Multiple suspicious raw code windows detected in sampled content");
    }

    if (shouldAnalyzePE && peInfo.isPE)
    {
        if (peInfo.possiblePackedFile)
        {
            risk.Add(ScaleAmbiguousExecutionRisk(peInfo.packerScore >= 40 ? 12 : 8, trustedSignedArtifact, trustedPublisher, false, false), "Packer-like PE structure detected");
        }
        if (peInfo.hasOverlay)
        {
            const int overlayRisk = peInfo.overlaySize > (512 * 1024) ? 12 : (peInfo.overlaySize > 10240 ? 8 : 4);
            risk.Add(ScaleAmbiguousExecutionRisk(overlayRisk, trustedSignedArtifact, trustedPublisher, false, false), "Overlay data detected in executable");
        }
        if (peInfo.hasTlsCallbacks)
        {
            risk.Add(ScaleAmbiguousExecutionRisk(8, trustedSignedArtifact, trustedPublisher, false, false), "TLS callbacks detected");
        }
        if (peInfo.entryPointOutsideExecutableSection)
        {
            risk.Add(20, "Entry point is outside executable section");
        }
        if (peInfo.hasAntiDebugIndicators)
        {
            risk.Add(ScaleAmbiguousExecutionRisk(peInfo.antiDebugIndicatorCount >= 3 ? 8 : 5, trustedSignedArtifact, trustedPublisher, false, false), "Anti-debug indicators detected in executable");
        }
        if (importInfo.suspiciousImportCount >= 4)
        {
            risk.Add(ScaleAmbiguousExecutionRisk(importInfo.suspiciousImportCount >= 8 ? 18 : 10, trustedSignedArtifact, trustedPublisher, false, false), "Multiple suspicious imported APIs detected");
        }
        else if (importInfo.suspiciousImportCount > 0)
        {
            risk.Add(ScaleAmbiguousExecutionRisk(5, trustedSignedArtifact, trustedPublisher, false, false), "Suspicious imported APIs detected");
        }
        for (const auto& note : importInfo.notes)
        {
            if (note == "Potential process injection import pattern detected")
            {
                risk.Add(ScaleAmbiguousExecutionRisk(20, trustedSignedArtifact, trustedPublisher, false, false), "Potential process injection pattern detected");
                scoredInjection = true;
            }
            else if (note == "Download-and-execute import pattern detected")
            {
                risk.Add(ScaleAmbiguousExecutionRisk(14, trustedSignedArtifact, trustedPublisher, false, false), "Download-and-execute pattern detected");
                scoredDownloader = true;
            }
            else if (note == "Anti-analysis import pattern detected")
            {
                risk.Add(ScaleAmbiguousExecutionRisk(8, trustedSignedArtifact, trustedPublisher, false, false), "Anti-analysis related imports detected");
                scoredEvasion = true;
            }
        }

        if (peInfo.packerScore >= 40)
        {
            risk.Add(ScaleAmbiguousExecutionRisk(12, trustedSignedArtifact, trustedPublisher, false, false), "Strong packer or obfuscation score detected");
        }
        else if (peInfo.packerScore >= 20)
        {
            risk.Add(ScaleAmbiguousExecutionRisk(7, trustedSignedArtifact, trustedPublisher, false, false), "Moderate packer or obfuscation score detected");
        }

        if (peInfo.hasSuspiciousEntrypointStub)
        {
            risk.Add(ScaleAmbiguousExecutionRisk(7, trustedSignedArtifact, trustedPublisher, false, false), "Stub-like entrypoint behavior detected");
        }
        if (peInfo.hasShellcodeLikeEntrypoint)
        {
            risk.Add(ScaleAmbiguousExecutionRisk(8, trustedSignedArtifact, trustedPublisher, false, false), "Entrypoint bytes look shellcode-like or unusually sparse");
        }
    }

    ReportProgress(progressCallback, modeLabel, "Extracting indicators", "Filtering noise, classifying embedded indicators, and identifying known libraries", info.size, info.size, 84);
    auto indicatorPair = indicatorFuture.get();
    indicators = std::move(indicatorPair.first);
    indicatorTaskMs = indicatorPair.second;
    std::string searchableText = info.name + "\n" + info.path + "\n" + detectedType + "\n" + realType + "\n";
    for (const auto& s : info.suspiciousStrings) searchableText += s + "\n";
    for (const auto& s : indicators.urls) searchableText += s + "\n";
    for (const auto& s : indicators.domains) searchableText += s + "\n";
    for (const auto& s : indicators.ips) searchableText += s + "\n";
    for (const auto& s : indicators.suspiciousCommands) searchableText += s + "\n";
    for (const auto& s : importInfo.allImportedFunctions) searchableText += s + "\n";
    for (const auto& s : peInfo.sectionNames) searchableText += s + "\n";
    ApplyCustomRules(LoadCustomRules(), searchableText, indicators);

    auto yaraFuture = scheduler.Submit([filePath, searchableText]() {
        return MeasureTaskMs([&]() { return RunLightweightYaraScan(filePath, searchableText); });
    });
    auto deobfuscationFuture = scheduler.Submit([searchableText, indicators]() {
        return MeasureTaskMs([&]() { return AnalyzeDeobfuscation(searchableText, indicators); });
    });
    auto iocFuture = scheduler.Submit([indicators]() {
        return MeasureTaskMs([&]() { return AnalyzeIocIntelligence(indicators); });
    });
    auto pluginFuture = scheduler.Submit([filePath, searchableText]() {
        return MeasureTaskMs([&]() { return RunPluginRulePackScan(filePath, searchableText); });
    });
    auto memoryFuture = scheduler.Submit([info]() {
        return MeasureTaskMs([&]() { return AnalyzeRuntimeMemoryContext(info); });
    });
    auto mlFuture = scheduler.Submit([info, peInfo, importInfo, indicators, sigInfo]() {
        return MeasureTaskMs([&]() { return RunLightweightMlAssessment(info, peInfo, importInfo, indicators, sigInfo); });
    });

    auto yaraPair = yaraFuture.get();
    const YaraScanResult yaraResult = std::move(yaraPair.first);
    yaraTaskMs = yaraPair.second;

    auto deobPair = deobfuscationFuture.get();
    const DeobfuscationResult deobResult = std::move(deobPair.first);
    deobTaskMs = deobPair.second;

    auto iocPair = iocFuture.get();
    const IocIntelligenceResult iocIntelligence = std::move(iocPair.first);
    iocTaskMs = iocPair.second;

    auto pluginPair = pluginFuture.get();
    const std::vector<PluginMatch> pluginMatches = std::move(pluginPair.first);
    pluginTaskMs = pluginPair.second;

    auto memoryPair = memoryFuture.get();
    const MemoryScannerResult memoryScan = std::move(memoryPair.first);
    memoryTaskMs = memoryPair.second;

    auto mlPair = mlFuture.get();
    const MlAssessmentResult mlAssessment = std::move(mlPair.first);
    mlTaskMs = mlPair.second;
    // installer context is computed once because it influences many later dampening decisions.
    const bool likelyLegitimateBootstrapper = IsLikelyLegitimateBootstrapper(info, sigInfo, peInfo, indicators);
    const bool trustedSignedPe = shouldAnalyzePE && peInfo.isPE && trustedSignedArtifact;
    const bool developerAnalysisContext = IsDeveloperOrSecurityToolContext(info, indicators);
    const bool localDevelopmentBuild = LooksLikeLocalDevelopmentBuild(info);
    const std::vector<std::string> contextTags = BuildContextTags(developerAnalysisContext, localDevelopmentBuild, trustedPublisher, likelyLegitimateBootstrapper);

    if (!info.suspiciousStrings.empty() || !indicators.behaviorHighlights.empty())
    {
        ReportProgress(progressCallback, modeLabel, "Applying behavioral heuristics", "Correlating extracted strings, classified indicators, PE findings, and reputation into final threat score", info.size, info.size, 86);

        const auto hasString = [&](const std::string& needle) {
            return std::find(info.suspiciousStrings.begin(), info.suspiciousStrings.end(), needle) != info.suspiciousStrings.end();
        };

        if (hasString("Ransomware shadow-copy tampering indicator") || hasString("Backup catalog deletion indicator") || hasString("Boot configuration tampering indicator"))
        {
            risk.Add(ScaleStringOnlyRisk(16, std::max(1u, indicators.ransomwareEvidenceCount), developerAnalysisContext), "Ransomware-related destructive command patterns detected");
            scoredRansomware = true;
        }
        if (hasString("Potential spyware / keylogger indicator"))
        {
            risk.Add(ScaleStringOnlyRisk(10, std::max(1u, indicators.keyloggingEvidenceCount), developerAnalysisContext), "Spyware / keylogging related strings detected");
            scoredSpyware = true;
        }
        if (hasString("Credential theft browser database reference"))
        {
            risk.Add(ScaleStringOnlyRisk(10, std::max(1u, indicators.credentialTheftEvidenceCount), developerAnalysisContext), "Credential theft related browser artifact references detected");
            scoredCredential = true;
        }
        if (hasString("Download-and-execute indicator") || hasString("PowerShell web request indicator"))
        {
            risk.Add(ScaleStringOnlyRisk(9, std::max(1u, indicators.downloaderEvidenceCount), developerAnalysisContext), "Payload delivery or downloader style behavior detected");
            scoredDownloader = true;
        }
        if (indicators.hasPersistenceTraits)
        {
            risk.Add(ScaleStringOnlyRisk(likelyLegitimateBootstrapper ? 4 : 10, indicators.persistenceEvidenceCount, developerAnalysisContext), "Persistence-related behavior detected");
            scoredPersistence = true;
        }
        if (indicators.hasInjectionTraits)
        {
            risk.Add(ScaleStringOnlyRisk(14, indicators.injectionEvidenceCount, developerAnalysisContext), "Injection or loader-related behavior detected");
            scoredInjection = true;
        }
        if (indicators.hasEvasionTraits)
        {
            risk.Add(ScaleStringOnlyRisk(likelyLegitimateBootstrapper || trustedPublisher ? 4 : 9, indicators.evasionEvidenceCount, developerAnalysisContext), "Anti-analysis or evasion behavior detected");
            scoredEvasion = true;
        }
        if (indicators.hasDownloaderTraits && !scoredDownloader)
        {
            risk.Add(ScaleStringOnlyRisk(likelyLegitimateBootstrapper ? 4 : 9, indicators.downloaderEvidenceCount, developerAnalysisContext), "Downloader behavior detected");
            scoredDownloader = true;
        }
        if (indicators.hasRansomwareTraits && !scoredRansomware)
        {
            risk.Add(ScaleStringOnlyRisk(14, indicators.ransomwareEvidenceCount, developerAnalysisContext), "Ransomware-related behavior detected");
            scoredRansomware = true;
        }
        if ((indicators.hasSpywareTraits || indicators.hasKeyloggingTraits) && !scoredSpyware)
        {
            risk.Add(ScaleStringOnlyRisk(10, std::max(indicators.spywareEvidenceCount, indicators.keyloggingEvidenceCount), developerAnalysisContext), "Spyware or keylogging-related behavior detected");
            scoredSpyware = true;
        }
        if (indicators.hasCredentialTheftTraits && !scoredCredential)
        {
            risk.Add(ScaleStringOnlyRisk(10, indicators.credentialTheftEvidenceCount, developerAnalysisContext), "Credential theft-related behavior detected");
            scoredCredential = true;
        }
    }

    // this summary acts as the merge point for higher-level narratives and report sections.
    AdvancedAnalysisSummary advancedSummary = BuildAdvancedAnalysisSummary(info, peInfo, importInfo, indicators, sigInfo);
    advancedSummary.analysisContextTags = contextTags;
    advancedSummary.yaraMatches = BuildYaraMatchLabels(yaraResult);
    advancedSummary.deobfuscationFindings = deobResult.findings;
    advancedSummary.deobfuscatedArtifacts = deobResult.decodedArtifacts;
    advancedSummary.iocIntelligenceSummary = iocIntelligence.summary;
    advancedSummary.pluginMatches = BuildPluginLabels(pluginMatches);
    advancedSummary.runtimeMemoryFindings = memoryScan.findings;
    advancedSummary.schedulerProfile = schedulerProfile.label + " (logical cores: " + std::to_string(schedulerProfile.logicalCores) + ", workers: " + std::to_string(pipelineWorkers) + ", mode: " + std::string(allowParallel ? "parallel pipeline" : "single-worker fallback") + ")";
    advancedSummary.mlAssessmentLabel = mlAssessment.label;
    advancedSummary.mlAssessmentReason = mlAssessment.confidence + " confidence lightweight model score " + std::to_string(mlAssessment.score);
    advancedSummary.mlFeatureNotes = mlAssessment.featureNotes;
    advancedSummary.mitreTechniques = BuildMitreTechniqueLabels(info, indicators, importInfo, peInfo);
    // behavior synthesis turns dispersed low-level hints into analyst-friendly runtime stories.
    const SimulatedBehaviorReport simulatedBehavior = BuildSimulatedBehaviorReport(info, indicators, importInfo, peInfo);
    advancedSummary.simulatedBehaviors = simulatedBehavior.behaviors;
    advancedSummary.behaviorTimeline = simulatedBehavior.timelineSteps;
    const EvasionAnalysisResult evasionResult = AnalyzeEvasionSignals(info, peInfo, importInfo, indicators);
    advancedSummary.evasionFindings = evasionResult.findings;
    if (!evasionResult.findings.empty())
    {
        const int evasionCap = likelyLegitimateBootstrapper ? 4 : (trustedPublisher ? 6 : 12);
        risk.Add(std::min(evasionResult.scoreBoost, evasionCap), "Evasion-aware analysis found concealment or anti-analysis patterns");
    }
    // capability labels only score when there is enough underlying evidence to back them.
    for (const auto& capability : advancedSummary.capabilities)
    {
        if ((capability == "Process Injection" || capability == "Process Injection / Loader") && !scoredInjection)
        {
            const bool strongInjectionEvidence = indicators.injectionEvidenceCount >= 2 ||
                std::find(importInfo.notes.begin(), importInfo.notes.end(), "Potential process injection import pattern detected") != importInfo.notes.end();
            if (strongInjectionEvidence)
            {
                risk.Add(ScaleCorrelationRisk(trustedPublisher ? 3 : 8, developerAnalysisContext, trustedPublisher, likelyLegitimateBootstrapper), "Capability engine detected process injection or loader behavior");
                scoredInjection = true;
            }
        }
        else if (capability == "Anti-Analysis / Evasion" && !scoredEvasion)
        {
            const bool strongEvasionEvidence = indicators.evasionEvidenceCount >= 2 || peInfo.antiDebugIndicatorCount >= 3;
            if (strongEvasionEvidence)
            {
                risk.Add(ScaleCorrelationRisk(trustedPublisher ? 1 : 5, developerAnalysisContext, trustedPublisher, likelyLegitimateBootstrapper), "Capability engine detected anti-analysis or evasion behavior");
                scoredEvasion = true;
            }
        }
        else if (capability == "Credential Theft" && !scoredCredential)
        {
            if (indicators.credentialTheftEvidenceCount >= 2)
            {
                risk.Add(ScaleCorrelationRisk(8, developerAnalysisContext, trustedPublisher, likelyLegitimateBootstrapper), "Capability engine detected credential theft behavior");
                scoredCredential = true;
            }
        }
        else if (capability == "Ransomware Behavior" && !scoredRansomware)
        {
            if (indicators.ransomwareEvidenceCount >= 2)
            {
                risk.Add(ScaleCorrelationRisk(10, developerAnalysisContext, trustedPublisher, likelyLegitimateBootstrapper), "Capability engine detected ransomware-oriented behavior");
                scoredRansomware = true;
            }
        }
    }

    if (!advancedSummary.correlationHighlights.empty())
    {
        const bool strongCorrelationContext = yaraResult.matches.size() > 0 ||
            (indicators.injectionEvidenceCount >= 2) ||
            (indicators.ransomwareEvidenceCount >= 2) ||
            (!evasionResult.findings.empty() && !trustedPublisher);
        if (strongCorrelationContext)
        {
            const int perHighlight = ScaleCorrelationRisk(3, developerAnalysisContext, trustedPublisher, likelyLegitimateBootstrapper);
            risk.Add(static_cast<int>(std::min<std::size_t>(advancedSummary.correlationHighlights.size(), 2)) * perHighlight, "Multiple analysis components correlate into higher-confidence suspicious patterns");
        }
    }

    // yara hits are still damped by trusted context because dev tools can self-match benign strings.
    if (!yaraResult.matches.empty())
    {
        int yaraBoost = 0;
        for (const auto& match : yaraResult.matches)
            yaraBoost += std::max(2, match.scoreBoost);
        if (developerAnalysisContext)
            yaraBoost = std::max(2, yaraBoost / 2);
        if (trustedPublisher)
            yaraBoost = std::max(2, yaraBoost / 2);
        risk.Add(std::min(yaraBoost, 24), "Lightweight YARA rules matched suspicious content patterns");
    }
    if (!deobResult.findings.empty())
        risk.Add(std::min(10, deobResult.scoreBoost), "Static deobfuscation recovered suspicious embedded content");
    if (!pluginMatches.empty())
    {
        int pluginBoost = 0;
        for (const auto& match : pluginMatches)
            pluginBoost += match.scoreBoost;
        risk.Add(std::min(12, pluginBoost), "Plugin rule packs matched suspicious workflow patterns");
    }
    if (mlAssessment.label == "Malicious-leaning")
        risk.Add(8, "Lightweight ML assessment leaned malicious");
    else if (mlAssessment.label == "Suspicious-leaning")
        risk.Add(4, "Lightweight ML assessment leaned suspicious");

    // apply a final damping pass when the sample looks like a legitimate signed bootstrapper with only ambiguous loader traits.
    const bool lowConfidenceHeuristicOnly = yaraResult.matches.empty() &&
        !embeddedPayloadInfo.foundEmbeddedPE &&
        indicators.injectionEvidenceCount == 0 &&
        indicators.ransomwareEvidenceCount == 0 &&
        indicators.credentialTheftEvidenceCount == 0;
    if (trustedSignedPe && likelyLegitimateBootstrapper && lowConfidenceHeuristicOnly)
    {
        risk.Add(-12, "Trusted signed bootstrapper with only ambiguous loader-style heuristics reduces risk");
    }

    if (developerAnalysisContext)
    {
        risk.Add(-16, "Security analysis / developer tool context reduces string-based risk");
    }
    if (localDevelopmentBuild)
    {
        risk.Add(-8, "Local development build path reduces suspicion for unsigned debug binaries");
    }

    const bool qtContextPresent = HasEmbeddedLibraryToken(indicators, "qt");
    const bool benignLeanWithLowSignal = developerAnalysisContext &&
        (localDevelopmentBuild || qtContextPresent) &&
        mlAssessment.label == "Benign-leaning" &&
        yaraResult.matches.empty() &&
        peInfo.packerScore < 25 &&
        !embeddedPayloadInfo.foundEmbeddedPE &&
        !embeddedPayloadInfo.foundShellcodeLikeBlob &&
        !indicators.hasRansomwareTraits &&
        !indicators.hasCredentialTheftTraits;
    if (benignLeanWithLowSignal)
    {
        // dampen self-scan and local security-tool false positives when the stack looks like a legitimate qt/dev build
        risk.Add(-14, "Developer/security tool context with benign-leaning model and low-signal evidence reduces false positives");
    }

    if (likelyLegitimateBootstrapper)
    {
        risk.Add(-30, "Signed installer or bootstrapper context reduces risk");
    }
    else if (trustedPublisher)
    {
        risk.Add(-12, "Trusted publisher context reduces risk");
    }

    // reputation is left late because the local heuristics should still stand on their own.
    ReportProgress(progressCallback, modeLabel, "Querying reputation services", "Checking SHA-256 against VirusTotal to reduce false positives and add reputation context", info.size, info.size, 92);
    ReputationResult rep;
    bool hasRep = false;
    if (!info.sha256.empty() && !vtApiKey.empty() && vtApiKey.rfind("DEBUG_ERR_", 0) != 0)
    {
        const auto reputationStarted = std::chrono::steady_clock::now();
        rep = QueryVirusTotalByHash(info.sha256, vtApiKey);
        reputationTaskMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - reputationStarted).count();
        hasRep = true;
        if (rep.httpStatusCode == 200 && rep.success)
        {
            if (rep.maliciousDetections >= 5)
            {
                risk.Add(40, "Multiple VirusTotal engines detected the file as malicious");
            }
            else if (rep.maliciousDetections > 0)
            {
                risk.Add(28, "VirusTotal detected the file as malicious");
            }
            else if (rep.suspiciousDetections > 0)
            {
                risk.Add(16, "VirusTotal detected the file as suspicious");
            }
            else
            {
                risk.Add(-(heavyMode ? 15 : 12), "No detections from VirusTotal engines");
                if (trustedSignedPe && likelyLegitimateBootstrapper && lowConfidenceHeuristicOnly)
                    risk.Add(-8, "Reputation cleanly aligns with trusted signed bootstrapper context");
                if (benignLeanWithLowSignal)
                    risk.Add(-8, "Clean reputation aligns with developer/security tool context");
            }
        }
    }

    const EvidenceCalibrationResult evidenceCalibration = BuildEvidenceCalibration(info,
                                                                                   peInfo,
                                                                                   importInfo,
                                                                                   indicators,
                                                                                   embeddedPayloadInfo,
                                                                                   sigInfo,
                                                                                   !yaraResult.matches.empty(),
                                                                                   !pluginMatches.empty(),
                                                                                   hasRep,
                                                                                   rep,
                                                                                   trustedPublisher,
                                                                                   trustedSignedPe,
                                                                                   likelyLegitimateBootstrapper);
    if (evidenceCalibration.riskDelta != 0)
        risk.Add(evidenceCalibration.riskDelta, evidenceCalibration.riskDelta > 0
            ? "Context-aware calibration escalated corroborated reversing signals"
            : "Context-aware calibration reduced ambiguous low-level evidence");
    advancedSummary.evidenceCalibrationNotes = evidenceCalibration.calibrationNotes;
    const bool hasEmbeddedSignalForDisposition = embeddedPayloadInfo.foundEmbeddedPE ||
        embeddedPayloadInfo.foundShellcodeLikeBlob ||
        embeddedPayloadInfo.suspiciousWindowCount > 0 ||
        !embeddedPayloadInfo.maskedPatternFindings.empty();
    advancedSummary.embeddedPayloadDisposition = hasEmbeddedSignalForDisposition
        ? (evidenceCalibration.embeddedPayloadDisposition.empty()
            ? embeddedPayloadInfo.signalReliability + std::string(" reliability low-level signal")
            : evidenceCalibration.embeddedPayloadDisposition)
        : std::string();
    for (const auto& item : evidenceCalibration.legitimateContext)
        AddReasonIfMissing(advancedSummary.legitimateContext, item);
    for (const auto& item : evidenceCalibration.correlationHighlights)
        AddReasonIfMissing(advancedSummary.correlationHighlights, item);
    for (const auto& item : evidenceCalibration.userFacingHighlights)
        AddReasonIfMissing(advancedSummary.userFacingHighlights, item);
    for (const auto& item : evidenceCalibration.confidenceNotes)
        AddReasonIfMissing(advancedSummary.confidenceBreakdown, item);

    risk.Clamp();
    // freeze the score only after all dampening and correlation passes have finished.
    const int finalRiskScore = risk.Score();
    const std::vector<std::string> finalReasons = BuildCondensedReasons(risk.Reasons());
    const std::string finalVerdict = VerdictLabelFromScore(finalRiskScore);
    const bool hasReputationContext = hasRep && (rep.success || rep.httpStatusCode > 0);
    const ConfidenceResult confidence = BuildConfidenceResult(advancedSummary, finalRiskScore, !yaraResult.matches.empty(), hasReputationContext, sigInfo.isSigned && sigInfo.signatureValid);
    advancedSummary.confidenceLabel = confidence.label;
    advancedSummary.confidenceReason = confidence.rationale;
    const std::vector<std::string> preservedConfidenceNotes = advancedSummary.confidenceBreakdown;
    advancedSummary.confidenceBreakdown = confidence.breakdown;
    for (const auto& item : preservedConfidenceNotes)
        AddReasonIfMissing(advancedSummary.confidenceBreakdown, item);
    if (benignLeanWithLowSignal)
        AddReasonIfMissing(advancedSummary.legitimateContext, "Qt/developer build context plus low-signal evidence reduced false-positive pressure");

    const nlohmann::json jsonReport = BuildAnalysisJson(info, peInfo, importInfo, indicators, sigInfo, advancedSummary, finalRiskScore, finalVerdict, finalReasons, detectedType, realType, typeMismatch);

    ReportProgress(progressCallback, modeLabel, "Finalizing report", "Building final scan report, reasons, and user notice about heuristic false positives", info.size, info.size, 98);

    std::string result = "BinaryLens Scan Result\r\n\r\n";
    AddLine(result, "Target Type: File");
    AddLine(result, "Target: " + info.path);

    AddSection(result, "File Information");
    AddLine(result, "Analysis Mode: " + modeLabel + (heavyMode ? " (512 MB+)" : ""));
    AddLine(result, "File Name: " + info.name);
    AddLine(result, "Extension: " + (info.extension.empty() ? std::string("[none]") : info.extension));
    AddLine(result, "File Size: " + FormatFileSize(info.size) + " (" + std::to_string(info.size) + " bytes)");
    AddLine(result, std::string("Readable: ") + (info.readable ? "Yes" : "No"));
    AddLine(result, "Entropy: " + FormatDouble(info.entropy, 2));
    AddLine(result, "Entropy Level: " + GetEntropyLevel(info.entropy));
    AddLine(result, "Detected Type: " + detectedType);
    AddLine(result, "Real Type: " + realType);
    if (typeMismatch)
        AddLine(result, "Type Mismatch: Possible spoofed extension");

    AddSection(result, "Hash Information");
    AddLine(result, "SHA-256: " + (info.sha256.empty() ? std::string("[unavailable]") : info.sha256));

    AddSection(result, "Executive Summary");
    AddLine(result, "Verdict: " + finalVerdict);
    AddLine(result, "Risk Score: " + std::to_string(finalRiskScore) + "%");
    AddLine(result, "Confidence: " + confidence.label + " (" + confidence.rationale + ")");
    AddLine(result, "Target Profile: " + detectedType + " / " + realType);
    AddLine(result, "Summary:");
    AddTopList(result, BuildKeyEvidenceOverview(peInfo, importInfo, scriptAbuseInfo, embeddedPayloadInfo, advancedSummary, sigInfo, finalRiskScore, finalVerdict), 8);

    const std::vector<std::string> primaryTechnicalFindings = BuildPrimaryTechnicalFindings(info, peInfo, importInfo, scriptAbuseInfo, embeddedPayloadInfo, advancedSummary);
    if (!primaryTechnicalFindings.empty())
    {
        AddSection(result, "Primary Technical Findings");
        AddTopList(result, primaryTechnicalFindings, 8);
    }

    if (shouldAnalyzePE)
    {
        AddSection(result, "Technical Evidence / PE Analysis");
        if (!peInfo.fileOpened)
            AddLine(result, "PE Status: Could not open file");
        else if (!peInfo.isPE)
            AddLine(result, "PE Status: Extension suggests executable but file is not a valid PE");
        else
        {
            AddLine(result, "PE Status: Valid Portable Executable");
            AddLine(result, peInfo.is64Bit ? "Architecture: 64-bit" : "Architecture: 32-bit");
            AddLine(result, "Sections: " + std::to_string(peInfo.numberOfSections));
            AddLine(result, "Entry Point RVA: " + std::to_string(peInfo.entryPoint));
            AddLine(result, "Image Size: " + std::to_string(peInfo.imageSize) + " bytes");
            if (!peInfo.entryPointSectionName.empty())
                AddLine(result, "Entry Point Section: " + peInfo.entryPointSectionName);
            if (peInfo.hasOverlay)
                AddLine(result, "Overlay Size: " + std::to_string(peInfo.overlaySize) + " bytes");
            if (peInfo.hasTlsCallbacks)
                AddLine(result, "TLS Callbacks: Present");
            if (peInfo.hasAntiDebugIndicators)
                AddLine(result, "Anti-Debug Indicators: " + std::to_string(peInfo.antiDebugIndicatorCount));
            if (!peInfo.sectionNames.empty())
            {
                std::string sections = "Section Names: ";
                for (size_t i = 0; i < peInfo.sectionNames.size(); ++i)
                {
                    sections += peInfo.sectionNames[i];
                    if (i + 1 < peInfo.sectionNames.size())
                        sections += ", ";
                }
                AddLine(result, sections);
            }
            std::vector<std::string> peStructureIndicators;
            for (const auto& item : peInfo.suspiciousIndicators)
            {
                if (ContainsAnyToken(item, {"entrypoint asm profile", "anti-debug indicator found"}))
                    continue;
                peStructureIndicators.push_back(item);
            }
            if (!peStructureIndicators.empty())
            {
                AddLine(result, "PE Indicators:");
                for (const auto& item : peStructureIndicators)
                    AddLine(result, "- " + item);
            }
        }
    }

    if (shouldCheckSignatureInfo)
    {
        AddSection(result, "Technical Evidence / Signature Analysis");
        AddLine(result, std::string("Signed: ") + (sigInfo.isSigned ? "Yes" : "No"));
        AddLine(result, std::string("Signature Valid: ") + (sigInfo.signatureValid ? "Yes" : "No"));
        AddLine(result, "Publisher: " + (sigInfo.hasPublisher ? sigInfo.publisher : std::string("[unavailable]")));
        AddLine(result, "Summary: " + sigInfo.summary);
        if (sigInfo.isSigned && sigInfo.signatureValid && trustedPublisher)
            AddLine(result, "Trust Context: Known publisher context detected");
    }

    if (shouldAnalyzePE && peInfo.isPE)
    {
        AddSection(result, "Technical Evidence / PE Imports Analysis");
        AddLine(result, std::string("Import Table Parsed: ") + (importInfo.importTableParsed ? "Yes" : "No"));
        AddLine(result, "Total Imports: " + std::to_string(importInfo.totalImports));
        AddLine(result, "Suspicious Imports Detected: " + std::to_string(importInfo.suspiciousImportCount));
        for (const auto& item : importInfo.suspiciousImports)
            AddLine(result, "- " + item);
        if (!importInfo.notes.empty())
        {
            AddLine(result, "Notes:");
            for (const auto& item : importInfo.notes)
                AddLine(result, "- " + item);
        }
    }

    if (info.archiveInspectionPerformed)
    {
        AddSection(result, "Technical Evidence / Archive Deep Inspection");
        AddLine(result, "Archive Entries Parsed: " + std::to_string(info.zipEntryCount));
        AddLine(result, "Suspicious Internal Entries: " + std::to_string(info.zipSuspiciousEntryCount));
        AddLine(result, std::string("Contains Executable Payloads: ") + (info.archiveContainsExecutable ? "Yes" : "No"));
        AddLine(result, std::string("Contains Script Payloads: ") + (info.archiveContainsScript ? "Yes" : "No"));
        AddLine(result, std::string("Contains Shortcut Payloads: ") + (info.archiveContainsShortcut ? "Yes" : "No"));
        AddLine(result, std::string("Contains Nested Archives: ") + (info.archiveContainsNestedArchive ? "Yes" : "No"));
        AddLine(result, std::string("Contains Path Traversal Entries: ") + (info.archiveContainsPathTraversal ? "Yes" : "No"));
        if (!info.archiveNotes.empty())
        {
            AddLine(result, "Archive Notes:");
            AddTopList(result, info.archiveNotes, 6);
        }
        if (!info.zipSuspiciousEntries.empty())
        {
            AddLine(result, "Suspicious Archive Entries:");
            AddTopList(result, info.zipSuspiciousEntries, 8);
        }
    }

    if (!info.suspiciousStrings.empty() || !indicators.behaviorHighlights.empty() || !indicators.urls.empty() || !indicators.embeddedLibraries.empty())
    {
        AddSection(result, "Technical Evidence / String / Indicator Extraction");
        AddLine(result, "Indicator Engine: Noise-filtered and categorized output");
        AddLine(result, "Noise Filtered: " + std::to_string(indicators.filteredNoiseCount) + " embedded references removed for clarity");
        AddLine(result, "ASCII Strings Parsed: " + std::to_string(indicators.asciiStringCount));
        AddLine(result, "Unicode Strings Parsed: " + std::to_string(indicators.unicodeStringCount));
        if (!indicators.behaviorHighlights.empty() || !info.suspiciousStrings.empty())
        {
            AddLine(result, "Behavior Highlights:");
            if (!indicators.behaviorHighlights.empty())
                AddTopList(result, indicators.behaviorHighlights, 5);
            else
                AddTopList(result, info.suspiciousStrings, 5);
        }
        if (!indicators.matchedRules.empty())
        {
            AddLine(result, "Threat Categories:");
            AddTopList(result, indicators.matchedRules, 6);
        }
        if (!indicators.urls.empty() || !indicators.domains.empty() || !indicators.ips.empty())
        {
            AddLine(result, "Embedded Network Artifacts:");
            AddTopList(result, indicators.urls, 3);
            AddTopList(result, indicators.domains, 3);
            AddTopList(result, indicators.ips, 3);
        }
        if (!indicators.trustReferences.empty())
        {
            AddLine(result, "Embedded Certificate / Trust References:");
            AddTopList(result, indicators.trustReferences, 3);
        }
        if (!indicators.suspiciousCommands.empty())
        {
            AddLine(result, "Execution Artifacts:");
            AddTopList(result, indicators.suspiciousCommands, 5);
        }
        if (!indicators.embeddedLibraries.empty())
        {
            AddLine(result, "Known Embedded Libraries:");
            AddTopList(result, indicators.embeddedLibraries, 6);
        }
        if (!indicators.analysisToolReferences.empty())
        {
            AddLine(result, "Analysis / Developer Context:");
            AddTopList(result, indicators.analysisToolReferences, 5);
        }
    }

    if (scriptAbuseInfo.analyzed && scriptAbuseInfo.likelyScriptContent && (scriptAbuseInfo.score > 0 || !scriptAbuseInfo.findings.empty()))
    {
        AddSection(result, "Technical Evidence / Script Abuse Analysis");
        AddLine(result, "Likely Script Content: Yes");
        AddLine(result, "Script Abuse Score: " + std::to_string(scriptAbuseInfo.score));
        if (!scriptAbuseInfo.findings.empty())
            AddTopList(result, scriptAbuseInfo.findings, 10);
        else
            AddLine(result, "No standout script abuse traits were surfaced from the sampled content");
    }

    if (embeddedPayloadInfo.analyzed && (embeddedPayloadInfo.foundEmbeddedPE ||
                                         embeddedPayloadInfo.foundShellcodeLikeBlob ||
                                         embeddedPayloadInfo.foundExecutableArchiveLure ||
                                         embeddedPayloadInfo.suspiciousWindowCount > 0 ||
                                         !embeddedPayloadInfo.maskedPatternFindings.empty()))
    {
        AddSection(result, "Technical Evidence / Embedded Payload Analysis");
        AddLine(result, "Assembly Backend: " + std::string(embeddedPayloadInfo.usedNativeAsmBackend ? "Native x64 ASM" : "Portable C++ fallback"));
        AddLine(result, "Embedded PE Detected: " + std::string(embeddedPayloadInfo.foundEmbeddedPE ? "Yes" : "No"));
        AddLine(result, "Embedded PE Validation: " + std::string(embeddedPayloadInfo.validatedEmbeddedPE ? "Structurally consistent" : "Not corroborated"));
        if (embeddedPayloadInfo.foundEmbeddedPE)
            AddLine(result, "Embedded PE Offset: " + std::to_string(static_cast<unsigned long long>(embeddedPayloadInfo.embeddedPEOffset)));
        AddLine(result, "Shellcode-Like Blob Detected: " + std::string(embeddedPayloadInfo.foundShellcodeLikeBlob ? "Yes" : "No"));
        if (embeddedPayloadInfo.foundShellcodeLikeBlob)
            AddLine(result, "Shellcode-Like Blob Offset: " + std::to_string(static_cast<unsigned long long>(embeddedPayloadInfo.shellcodeOffset)));
        AddLine(result, "Signal Reliability: " + embeddedPayloadInfo.signalReliability);
        if (!advancedSummary.embeddedPayloadDisposition.empty())
            AddLine(result, "Disposition: " + advancedSummary.embeddedPayloadDisposition);
        AddLine(result, "Likely Compressed Noise: " + std::string(embeddedPayloadInfo.likelyCompressedNoise ? "Yes" : "No"));
        AddLine(result, "Suspicious Raw-Code Windows: " + std::to_string(embeddedPayloadInfo.suspiciousWindowCount));
        AddLine(result, "Compressed-Like Windows: " + std::to_string(embeddedPayloadInfo.compressedLikeWindowCount));
        if (!embeddedPayloadInfo.strongestProfileSummary.empty())
        {
            AddLine(result, "Strongest Raw-Code Window Offset: " + std::to_string(static_cast<unsigned long long>(embeddedPayloadInfo.strongestProfileOffset)));
            AddLine(result, "Strongest Raw-Code Profile: " + embeddedPayloadInfo.strongestProfileSummary);
            AddLine(result, "Strongest Opcode Suspicion Score: " + std::to_string(embeddedPayloadInfo.strongestOpcodeScore));
            AddLine(result, "Strongest Branch Opcode Count: " + std::to_string(embeddedPayloadInfo.strongestBranchOpcodeCount));
            AddLine(result, "Strongest Memory Walk Pattern Count: " + std::to_string(embeddedPayloadInfo.strongestMemoryAccessPatternCount));
            AddLine(result, "Strongest Printable Ratio: " + FormatDouble(embeddedPayloadInfo.strongestWindowPrintableRatio, 2));
            AddLine(result, "Strongest High-Bit Ratio: " + FormatDouble(embeddedPayloadInfo.strongestWindowHighBitRatio, 2));
            AddLine(result, "Strongest Zero-Byte Ratio: " + FormatDouble(embeddedPayloadInfo.strongestWindowZeroByteRatio, 2));
            AddLine(result, "Strongest Opcode-Lead Ratio: " + FormatDouble(embeddedPayloadInfo.strongestWindowOpcodeLeadRatio, 2));
        }
        AddLine(result, "Embedded Payload Score: " + std::to_string(embeddedPayloadInfo.score));
        AddTopList(result, embeddedPayloadInfo.findings, 8);
        if (!embeddedPayloadInfo.strongestProfileDetails.empty())
        {
            AddLine(result, "Embedded Payload Assembly Findings:");
            AddTopList(result, embeddedPayloadInfo.strongestProfileDetails, 8);
        }
        if (!embeddedPayloadInfo.contextNotes.empty())
        {
            AddLine(result, "Embedded Payload Context Notes:");
            AddTopList(result, embeddedPayloadInfo.contextNotes, 8);
        }
        if (!embeddedPayloadInfo.maskedPatternFindings.empty())
        {
            AddLine(result, "Masked Opcode Pattern Hits:");
            AddTopList(result, embeddedPayloadInfo.maskedPatternFindings, 6);
        }
    }

    AddSection(result, "Technical Evidence / YARA Analysis");
    AddLine(result, "Engine: Lightweight YARA-style matcher");
    AddLine(result, "Matches: " + std::to_string(advancedSummary.yaraMatches.size()));
    if (!advancedSummary.yaraMatches.empty())
        AddTopList(result, advancedSummary.yaraMatches, 8);
    else
        AddLine(result, "No YARA-like rules matched the current target");

    if (!advancedSummary.deobfuscationFindings.empty() || !advancedSummary.deobfuscatedArtifacts.empty())
    {
        AddSection(result, "Technical Evidence / Static Deobfuscation");
        if (!advancedSummary.deobfuscationFindings.empty())
            AddTopList(result, advancedSummary.deobfuscationFindings, 6);
        if (!advancedSummary.deobfuscatedArtifacts.empty())
        {
            AddLine(result, "Recovered Artifacts:");
            AddTopList(result, advancedSummary.deobfuscatedArtifacts, 4);
        }
    }

    if (!advancedSummary.simulatedBehaviors.empty())
    {
        AddSection(result, "Simulated Runtime Behavior");
        AddTopList(result, advancedSummary.simulatedBehaviors, 8);
    }
    if (!advancedSummary.behaviorTimeline.empty())
    {
        AddSection(result, "Behavior Timeline");
        AddTopList(result, advancedSummary.behaviorTimeline, 8);
    }

    if (!advancedSummary.evasionFindings.empty())
    {
        AddSection(result, "Technical Evidence / Evasion Analysis");
        AddTopList(result, advancedSummary.evasionFindings, 8);
    }

    if (!advancedSummary.analysisContextTags.empty())
    {
        AddSection(result, "Analysis Context");
        AddTopList(result, advancedSummary.analysisContextTags, 6);
    }
    if (!advancedSummary.iocIntelligenceSummary.empty())
    {
        AddSection(result, "Technical Evidence / IOC Intelligence");
        AddTopList(result, advancedSummary.iocIntelligenceSummary, 8);
    }
    if (!advancedSummary.runtimeMemoryFindings.empty())
    {
        AddSection(result, "Technical Evidence / Runtime Memory Context");
        AddTopList(result, advancedSummary.runtimeMemoryFindings, 6);
    }

    if (shouldAnalyzePE && peInfo.isPE)
    {
        AddSection(result, "Technical Evidence / Assembly / Low-Level Profiling");
        AddLine(result, "Assembly Backend: " + std::string(bl::asmbridge::IsAsmBackendAvailable() ? "Native x64 ASM" : "Portable C++ fallback"));
        AddLine(result, "Entrypoint Byte Window: " + (peInfo.entryPointBytes.empty() ? std::string("[unavailable]") : peInfo.entryPointBytes));
        AddLine(result, "ASM Profile Summary: " + (peInfo.asmEntrypointProfileSummary.empty() ? std::string("[none]") : peInfo.asmEntrypointProfileSummary));
        AddLine(result, "Opcode Suspicion Score: " + std::to_string(peInfo.asmSuspiciousOpcodeScore));
        AddLine(result, "Branch Opcode Count: " + std::to_string(peInfo.asmBranchOpcodeCount));
        AddLine(result, "Memory Walk Pattern Count: " + std::to_string(peInfo.asmMemoryAccessPatternCount));
        if (!peInfo.asmFeatureDetails.empty())
        {
            AddLine(result, "Assembly Findings:");
            AddTopList(result, peInfo.asmFeatureDetails, 10);
        }
        else
        {
            AddLine(result, "Assembly Findings: No standout low-level entrypoint traits were recorded in the profiled byte window");
        }
    }
    if (!advancedSummary.pluginMatches.empty())
    {
        AddSection(result, "Technical Evidence / Plugin Rule Packs");
        AddTopList(result, advancedSummary.pluginMatches, 6);
    }

    if (!advancedSummary.capabilities.empty())
    {
        AddSection(result, "Capability Correlation");
        AddTopList(result, advancedSummary.capabilities, 8);
    }
    if (!advancedSummary.mitreTechniques.empty())
    {
        AddSection(result, "MITRE ATT&CK Mapping");
        AddTopList(result, advancedSummary.mitreTechniques, 8);
    }

    AddSection(result, "Technical Evidence / Advanced PE Heuristics");
    if (shouldAnalyzePE && peInfo.isPE)
    {
        AddLine(result, "Packer Score: " + std::to_string(peInfo.packerScore));
        AddLine(result, "Packer Assessment: " + (advancedSummary.packerAssessment.empty() ? std::string("[none]") : advancedSummary.packerAssessment));
        AddLine(result, "Executable Sections: " + std::to_string(peInfo.executableSectionCount));
        AddLine(result, "RWX Sections: " + std::to_string(peInfo.writableExecutableSectionCount));
        AddLine(result, "High-Entropy Executable Sections: " + std::to_string(peInfo.highEntropyExecutableSectionCount));
        AddLine(result, "Resources Present: " + std::string(peInfo.hasResourceData ? "Yes" : "No"));
        if (peInfo.hasResourceData)
        {
            AddLine(result, "Resource Entry Count: " + std::to_string(peInfo.resourceEntryCount));
            AddLine(result, "Resource Assessment: " + advancedSummary.resourceAssessment);
        }
        AddLine(result, "Security Directory Present: " + std::string(peInfo.hasSecurityDirectory ? "Yes" : "No"));
        AddLine(result, "Debug Directory Present: " + std::string(peInfo.hasDebugDirectory ? "Yes" : "No"));
        AddLine(result, "Relocations Present: " + std::string(peInfo.hasRelocations ? "Yes" : "No"));
    }
    else
    {
        AddLine(result, "Advanced PE heuristics not applicable to this target.");
    }

    if (!advancedSummary.correlationHighlights.empty())
    {
        AddSection(result, "Evidence Correlation");
        AddTopList(result, advancedSummary.correlationHighlights, 6);
    }

    if (!advancedSummary.legitimateContext.empty())
    {
        AddSection(result, "Legitimate Context / Reductions");
        AddTopList(result, advancedSummary.legitimateContext, 6);
    }
    if (!advancedSummary.evidenceCalibrationNotes.empty())
    {
        AddSection(result, "Context-Aware Calibration");
        AddTopList(result, advancedSummary.evidenceCalibrationNotes, 6);
    }

    const std::vector<std::string> analystNotes = BuildAnalystNotes(advancedSummary, sigInfo, trustedPublisher, likelyLegitimateBootstrapper);
    if (!analystNotes.empty())
    {
        AddSection(result, "Analyst Notes");
        AddTopList(result, analystNotes, 8);
    }

    AddSection(result, "Reputation");
    if (hasRep && rep.httpStatusCode == 200 && rep.success)
    {
        AddLine(result, "VirusTotal Malicious: " + std::to_string(rep.maliciousDetections));
        AddLine(result, "VirusTotal Suspicious: " + std::to_string(rep.suspiciousDetections));
        AddLine(result, "VirusTotal Harmless: " + std::to_string(rep.harmlessDetections));
        AddLine(result, "VirusTotal Undetected: " + std::to_string(rep.undetectedDetections));
    }
    else if (!info.sha256.empty() && !vtApiKey.empty() && vtApiKey.rfind("DEBUG_ERR_", 0) != 0)
    {
        AddLine(result, "VirusTotal: Reputation could not be fully verified");
        if (!trustedPublisher)
            risk.Add(0, "VirusTotal reputation could not be fully verified");
    }
    else if (vtApiKey.empty())
    {
        // keep the ui clean when the key is missing or the config path is not resolved
        AddLine(result, "VirusTotal API key not configured");
    }
    else
    {
        AddLine(result, "SHA-256 hash unavailable");
    }

    AddSection(result, "Performance / Pipeline");
    AddLine(result, "Scheduler Profile: " + advancedSummary.schedulerProfile);
    AddLine(result, "Engine Timings: PE " + FormatMs(peTaskMs) + " | Signature " + FormatMs(signatureTaskMs) + " | Imports " + FormatMs(importTaskMs) + " | Indicators " + FormatMs(indicatorTaskMs) + " | YARA " + FormatMs(yaraTaskMs));
    AddLine(result, "Secondary Timings: Deobfuscation " + FormatMs(deobTaskMs) + " | IOC " + FormatMs(iocTaskMs) + " | Plugins " + FormatMs(pluginTaskMs) + " | Memory " + FormatMs(memoryTaskMs) + " | ML " + FormatMs(mlTaskMs) + " | Reputation " + FormatMs(reputationTaskMs));

    AddSection(result, "Lightweight ML Assessment");
    AddLine(result, "Model Leaning: " + advancedSummary.mlAssessmentLabel);
    AddLine(result, "Model Context: " + advancedSummary.mlAssessmentReason);
    if (!advancedSummary.mlFeatureNotes.empty())
        AddTopList(result, advancedSummary.mlFeatureNotes, 6);

    AddSection(result, "Decision Basis");
    AddLine(result, "Risk Score: " + std::to_string(finalRiskScore) + "%");
    AddLine(result, "Verdict: " + finalVerdict);
    AddLine(result, "Confidence: " + confidence.label + " (" + confidence.rationale + ")");
    AddTopList(result, BuildDecisionBasis(finalReasons, confidence, advancedSummary, hasReputationContext), 8);

    if (!advancedSummary.confidenceBreakdown.empty())
    {
        AddSection(result, "Confidence Breakdown");
        AddTopList(result, advancedSummary.confidenceBreakdown, 8);
    }

    AddSection(result, "Final Rationale");
    result += BuildReasonsBlock(finalReasons);

    AddSection(result, "Notice");
    AddLine(result, "This analysis is heuristic-based and there are real chances of false positives or false negatives.");
    AddLine(result, "Use the result as a strong signal, not as the only source of truth for malware classification.");

    AddLine(result, "Status: Analysis complete");

    std::vector<std::string> legitimateContext = advancedSummary.legitimateContext;
    if (trustedPublisher && std::find(legitimateContext.begin(), legitimateContext.end(), "Valid Authenticode signature present") == legitimateContext.end())
        legitimateContext.push_back("Known trusted publisher context detected");

    std::vector<std::string> iocSummary;
    for (const auto& value : indicators.urls) { if (iocSummary.size() >= 6) break; iocSummary.push_back("URL: " + value); }
    for (const auto& value : indicators.domains) { if (iocSummary.size() >= 6) break; iocSummary.push_back("Domain: " + value); }
    for (const auto& value : indicators.ips) { if (iocSummary.size() >= 6) break; iocSummary.push_back("IP: " + value); }
    for (const auto& value : indicators.suspiciousCommands) { if (iocSummary.size() >= 6) break; iocSummary.push_back("Command: " + value); }

    // build separate views from the same merged evidence so the ui can switch instantly.
    std::string analystView = result;
    std::string userView = BuildUserViewText("File", finalRiskScore, finalVerdict, finalReasons, legitimateContext, iocSummary, advancedSummary.yaraMatches, advancedSummary.simulatedBehaviors, advancedSummary.analysisContextTags);
    if (!advancedSummary.behaviorTimeline.empty())
    {
        AddSection(userView, "Behavior Timeline");
        AddTopList(userView, advancedSummary.behaviorTimeline, 5);
    }
    if (!advancedSummary.confidenceBreakdown.empty())
    {
        AddSection(userView, "Confidence Breakdown");
        AddTopList(userView, advancedSummary.confidenceBreakdown, 5);
    }
    std::string iocView = BuildIocExportText(indicators);
    if (!advancedSummary.iocIntelligenceSummary.empty())
    {
        AddSection(iocView, "IOC Intelligence");
        AddTopList(iocView, advancedSummary.iocIntelligenceSummary, 8);
    }

    AnalysisReportData reportData{ userView, analystView, iocView, jsonReport.dump(2) };
    SaveAnalysisCache(info, reportData);
    ReportProgress(progressCallback, modeLabel, "Analysis complete", "Report finished and ready for review", info.size, info.size, 100, 0, 0, 0.0, 0, heavyMode);
    return reportData;
}

// string-only wrapper used by callers that do not need the structured report object.
std::string RunFileAnalysis(const std::string& filePath, AnalysisProgressCallback progressCallback)
{
    return RunFileAnalysisDetailed(filePath, std::move(progressCallback)).textReport;
}
