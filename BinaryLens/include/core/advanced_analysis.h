#pragma once

// cross-engine correlation helpers that merge raw signals into higher-level context.
#include <algorithm>
#include <cctype>
#include <fstream>
#include <string>
#include <vector>

#include "analyzers/import_analyzer.h"
#include "analyzers/indicator_extractor.h"
#include "analyzers/pe_analyzer.h"
#include "scanners/file_scanner.h"
#include "services/signature_checker.h"
#include "third_party/json.hpp"

struct AdvancedAnalysisSummary
{
    std::vector<std::string> capabilities;
    std::vector<std::string> correlationHighlights;
    std::vector<std::string> ruleMatches;
    std::vector<std::string> yaraMatches;
    std::vector<std::string> simulatedBehaviors;
    std::vector<std::string> analysisContextTags;
    std::vector<std::string> evasionFindings;
    std::vector<std::string> deobfuscationFindings;
    std::vector<std::string> deobfuscatedArtifacts;
    std::vector<std::string> iocIntelligenceSummary;
    std::vector<std::string> confidenceBreakdown;
    std::vector<std::string> behaviorTimeline;
    std::vector<std::string> runtimeMemoryFindings;
    std::vector<std::string> pluginMatches;
    std::string confidenceLabel;
    std::string confidenceReason;
    std::string schedulerProfile;
    std::string mlAssessmentLabel;
    std::string mlAssessmentReason;
    std::vector<std::string> mlFeatureNotes;
    std::vector<std::string> userFacingHighlights;
    std::vector<std::string> legitimateContext;
    std::string packerAssessment;
    std::string resourceAssessment;
    std::string jsonReportPath;
};

inline std::string AdvancedToLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

inline bool AdvancedContains(const std::string& haystack, const std::string& needle)
{
    return AdvancedToLower(haystack).find(AdvancedToLower(needle)) != std::string::npos;
}

inline void AddAdvancedUnique(std::vector<std::string>& items, const std::string& value)
{
    if (value.empty())
        return;
    if (std::find(items.begin(), items.end(), value) == items.end())
        items.push_back(value);
}

inline AdvancedAnalysisSummary BuildAdvancedAnalysisSummary(const FileInfo& info,
                                                           const PEAnalysisResult& peInfo,
                                                           const ImportAnalysisResult& importInfo,
                                                           const Indicators& indicators,
                                                           const SignatureCheckResult& sigInfo)
{
    AdvancedAnalysisSummary summary;

    const bool trustedSigned = sigInfo.isSigned && sigInfo.signatureValid;
    const bool installerLike = indicators.hasInstallerTraits ||
        AdvancedContains(info.name, "setup") || AdvancedContains(info.name, "installer") || AdvancedContains(info.path, "bootstrap");

    for (const auto& cluster : importInfo.capabilityClusters)
    {
        if ((cluster == "Persistence" || cluster == "Discovery / Secret Access") && trustedSigned && installerLike)
            continue;
        AddAdvancedUnique(summary.capabilities, cluster);
    }

    if (indicators.hasDownloaderTraits)
        AddAdvancedUnique(summary.capabilities, "Downloader / Payload Retrieval");
    if (indicators.hasPersistenceTraits && (!trustedSigned || indicators.persistenceEvidenceCount >= 2))
        AddAdvancedUnique(summary.capabilities, "Persistence");
    if (indicators.hasInjectionTraits && indicators.injectionEvidenceCount >= 2)
        AddAdvancedUnique(summary.capabilities, "Process Injection / Loader");
    if (indicators.hasEvasionTraits || peInfo.hasAntiDebugIndicators)
        AddAdvancedUnique(summary.capabilities, "Anti-Analysis / Evasion");
    if (indicators.hasRansomwareTraits)
        AddAdvancedUnique(summary.capabilities, "Ransomware Behavior");
    if (indicators.hasSpywareTraits || indicators.hasKeyloggingTraits)
        AddAdvancedUnique(summary.capabilities, "Spyware / Keylogging");
    if (indicators.hasCredentialTheftTraits)
        AddAdvancedUnique(summary.capabilities, "Credential Theft");
    if (!indicators.urls.empty() || !indicators.ips.empty() || !indicators.domains.empty())
        AddAdvancedUnique(summary.capabilities, "Embedded Network Infrastructure");

    for (const auto& rule : indicators.matchedRules)
        AddAdvancedUnique(summary.ruleMatches, rule);

    if (peInfo.possiblePackedFile)
    {
        summary.packerAssessment = peInfo.likelyPackerFamily.empty() ? "Packed / obfuscated PE suspected" : peInfo.likelyPackerFamily;
        if (!trustedSigned || peInfo.highEntropyExecutableSectionCount > 0 || peInfo.writableExecutableSectionCount > 0 || peInfo.overlaySize >= (1024ULL * 1024ULL))
            AddAdvancedUnique(summary.correlationHighlights, "PE structure suggests packing or obfuscation");
    }
    else
    {
        summary.packerAssessment = "No strong packer signal";
    }

    if (peInfo.hasResourceData)
    {
        if (peInfo.resourceEntryCount >= 64)
            summary.resourceAssessment = "Large resource tree";
        else if (peInfo.resourceEntryCount > 0)
            summary.resourceAssessment = "Standard resource tree present";
        else
            summary.resourceAssessment = "Resources present but detailed enumeration was limited";
    }
    else
    {
        summary.resourceAssessment = "No PE resources detected";
    }

    if (peInfo.hasEntrypointJumpStub && peInfo.highEntropyExecutableSectionCount > 0)
        AddAdvancedUnique(summary.correlationHighlights, "Jump-stub entrypoint combined with high-entropy executable section");

    if (peInfo.hasSuspiciousEntrypointStub && importInfo.totalImports <= 20)
        AddAdvancedUnique(summary.correlationHighlights, "Small import surface plus stub-like entrypoint can indicate loader behavior");

    if (indicators.hasDownloaderTraits && (!indicators.urls.empty() || !indicators.domains.empty()))
        AddAdvancedUnique(summary.correlationHighlights, "Downloader traits align with embedded network artifacts");

    if (indicators.hasInjectionTraits && indicators.injectionEvidenceCount >= 2 && std::find(importInfo.capabilityClusters.begin(), importInfo.capabilityClusters.end(), "Process Injection") != importInfo.capabilityClusters.end())
        AddAdvancedUnique(summary.correlationHighlights, "Strings and imports both indicate process injection capability");

    if ((indicators.hasEvasionTraits || peInfo.hasAntiDebugIndicators) && peInfo.possiblePackedFile && (!trustedSigned || peInfo.highEntropyExecutableSectionCount > 0))
        AddAdvancedUnique(summary.correlationHighlights, "Packed / obfuscated PE also exposes anti-analysis traits");

    if (indicators.hasRansomwareTraits && indicators.hasPersistenceTraits)
        AddAdvancedUnique(summary.correlationHighlights, "Persistence artifacts appear alongside ransomware-oriented commands");

    if (indicators.hasCredentialTheftTraits && (!indicators.filePaths.empty() || !indicators.registryKeys.empty()))
        AddAdvancedUnique(summary.correlationHighlights, "Credential access artifacts line up with local path or registry references");

    if (!sigInfo.isSigned && peInfo.possiblePackedFile)
        AddAdvancedUnique(summary.correlationHighlights, "Unsigned executable plus packed layout increases suspicion");

    if (sigInfo.isSigned && sigInfo.signatureValid && peInfo.possiblePackedFile && !installerLike && !AdvancedContains(sigInfo.publisher, "microsoft"))
        AddAdvancedUnique(summary.correlationHighlights, "Packed layout exists even though the binary is signed; verify signer reputation carefully");

    if (info.doubleExtensionSuspicious && info.isPELike)
        AddAdvancedUnique(summary.correlationHighlights, "Executable content with spoof-like extension pattern detected");

    if (info.archiveInspectionPerformed)
    {
        if (info.archiveContainsExecutable || info.archiveContainsScript || info.archiveContainsShortcut)
            AddAdvancedUnique(summary.capabilities, "Archive Payload Delivery");
        if (info.archiveContainsLureAndExecutablePattern)
            AddAdvancedUnique(summary.correlationHighlights, "Archive lure naming aligns with active payload content");
        if (info.archiveContainsPathTraversal)
            AddAdvancedUnique(summary.correlationHighlights, "Archive contains path traversal style entries");
        if (!info.archiveNotes.empty())
            AddAdvancedUnique(summary.userFacingHighlights, "Archive deep inspection found suspicious internal content");
    }

    if (sigInfo.isSigned && sigInfo.signatureValid)
        AddAdvancedUnique(summary.legitimateContext, "Valid Authenticode signature present");
    if (!sigInfo.publisher.empty())
        AddAdvancedUnique(summary.legitimateContext, std::string("Publisher: ") + sigInfo.publisher);
    if (!indicators.trustReferences.empty())
        AddAdvancedUnique(summary.legitimateContext, "Embedded certificate or trust references detected");
    if (indicators.hasInstallerTraits)
        AddAdvancedUnique(summary.legitimateContext, "Installer / bootstrapper string context detected");

    if (!summary.capabilities.empty())
        AddAdvancedUnique(summary.userFacingHighlights, "Capability engine found behavior clusters worth analyst review");
    if (!summary.correlationHighlights.empty())
        AddAdvancedUnique(summary.userFacingHighlights, "Multiple technical signals reinforce each other");
    if (!summary.legitimateContext.empty())
        AddAdvancedUnique(summary.userFacingHighlights, "Legitimate context also exists and should reduce overreaction");

    return summary;
}

inline nlohmann::json BuildAnalysisJson(const FileInfo& info,
                                        const PEAnalysisResult& peInfo,
                                        const ImportAnalysisResult& importInfo,
                                        const Indicators& indicators,
                                        const SignatureCheckResult& sigInfo,
                                        const AdvancedAnalysisSummary& advanced,
                                        int finalRiskScore,
                                        const std::string& finalVerdict,
                                        const std::vector<std::string>& reasons,
                                        const std::string& detectedType,
                                        const std::string& realType,
                                        bool typeMismatch)
{
    nlohmann::json j;
    j["target_type"] = "file";
    j["path"] = info.path;
    j["name"] = info.name;
    j["extension"] = info.extension;
    j["size_bytes"] = info.size;
    j["sha256"] = info.sha256;
    j["entropy"] = info.entropy;
    j["detected_type"] = detectedType;
    j["real_type"] = realType;
    j["type_mismatch"] = typeMismatch;
    j["final_risk_score"] = finalRiskScore;
    j["final_verdict"] = finalVerdict;
    j["reasons"] = reasons;

    j["signature"] = {
        {"signed", sigInfo.isSigned},
        {"valid", sigInfo.signatureValid},
        {"publisher", sigInfo.publisher},
        {"summary", sigInfo.summary}
    };

    j["archive"] = {
        {"inspection_performed", info.archiveInspectionPerformed},
        {"entry_count", info.zipEntryCount},
        {"suspicious_entry_count", info.zipSuspiciousEntryCount},
        {"suspicious_entries", info.zipSuspiciousEntries},
        {"notes", info.archiveNotes},
        {"contains_executable", info.archiveContainsExecutable},
        {"contains_script", info.archiveContainsScript},
        {"contains_shortcut", info.archiveContainsShortcut},
        {"contains_nested_archive", info.archiveContainsNestedArchive},
        {"contains_suspicious_double_extension", info.archiveContainsSuspiciousDoubleExtension},
        {"contains_path_traversal", info.archiveContainsPathTraversal},
        {"contains_hidden_entries", info.archiveContainsHiddenEntries},
        {"contains_lure_and_executable_pattern", info.archiveContainsLureAndExecutablePattern}
    };

    j["pe"] = {
        {"is_pe", peInfo.isPE},
        {"is_64_bit", peInfo.is64Bit},
        {"sections", peInfo.numberOfSections},
        {"entry_point_rva", peInfo.entryPoint},
        {"entry_point_section", peInfo.entryPointSectionName},
        {"entry_point_bytes", peInfo.entryPointBytes},
        {"entry_point_heuristic", peInfo.entryPointHeuristic},
        {"asm_entrypoint_profile_summary", peInfo.asmEntrypointProfileSummary},
        {"asm_suspicious_opcode_score", peInfo.asmSuspiciousOpcodeScore},
        {"asm_branch_opcode_count", peInfo.asmBranchOpcodeCount},
        {"asm_memory_access_pattern_count", peInfo.asmMemoryAccessPatternCount},
        {"has_overlay", peInfo.hasOverlay},
        {"overlay_size", peInfo.overlaySize},
        {"has_tls", peInfo.hasTlsCallbacks},
        {"has_resources", peInfo.hasResourceData},
        {"resource_entries", peInfo.resourceEntryCount},
        {"has_debug_directory", peInfo.hasDebugDirectory},
        {"has_security_directory", peInfo.hasSecurityDirectory},
        {"has_relocations", peInfo.hasRelocations},
        {"high_entropy_executable_sections", peInfo.highEntropyExecutableSectionCount},
        {"writable_executable_sections", peInfo.writableExecutableSectionCount},
        {"packer_score", peInfo.packerScore},
        {"packer_family", peInfo.likelyPackerFamily},
        {"indicators", peInfo.suspiciousIndicators}
    };

    j["imports"] = {
        {"parsed", importInfo.importTableParsed},
        {"total", importInfo.totalImports},
        {"suspicious_count", importInfo.suspiciousImportCount},
        {"suspicious", importInfo.suspiciousImports},
        {"capabilities", importInfo.capabilityClusters},
        {"notes", importInfo.notes}
    };

    j["indicators"] = {
        {"ascii_string_count", indicators.asciiStringCount},
        {"unicode_string_count", indicators.unicodeStringCount},
        {"filtered_noise_count", indicators.filteredNoiseCount},
        {"urls", indicators.urls},
        {"ips", indicators.ips},
        {"domains", indicators.domains},
        {"emails", indicators.emails},
        {"file_paths", indicators.filePaths},
        {"registry_keys", indicators.registryKeys},
        {"commands", indicators.suspiciousCommands},
        {"base64_blobs", indicators.base64Blobs},
        {"libraries", indicators.embeddedLibraries},
        {"trust_references", indicators.trustReferences},
        {"analysis_tool_references", indicators.analysisToolReferences},
        {"behavior_highlights", indicators.behaviorHighlights},
        {"rules", indicators.matchedRules},
        {"security_analysis_context", indicators.hasSecurityAnalysisContext},
        {"downloader_evidence_count", indicators.downloaderEvidenceCount},
        {"ransomware_evidence_count", indicators.ransomwareEvidenceCount},
        {"spyware_evidence_count", indicators.spywareEvidenceCount},
        {"credential_theft_evidence_count", indicators.credentialTheftEvidenceCount},
        {"keylogging_evidence_count", indicators.keyloggingEvidenceCount},
        {"persistence_evidence_count", indicators.persistenceEvidenceCount},
        {"injection_evidence_count", indicators.injectionEvidenceCount},
        {"evasion_evidence_count", indicators.evasionEvidenceCount}
    };

    j["advanced"] = {
        {"capabilities", advanced.capabilities},
        {"correlation_highlights", advanced.correlationHighlights},
        {"yara_matches", advanced.yaraMatches},
        {"simulated_behaviors", advanced.simulatedBehaviors},
{"analysis_context_tags", advanced.analysisContextTags},
        {"evasion_findings", advanced.evasionFindings},
        {"deobfuscation_findings", advanced.deobfuscationFindings},
        {"deobfuscated_artifacts", advanced.deobfuscatedArtifacts},
        {"ioc_intelligence_summary", advanced.iocIntelligenceSummary},
        {"confidence_breakdown", advanced.confidenceBreakdown},
        {"behavior_timeline", advanced.behaviorTimeline},
        {"runtime_memory_findings", advanced.runtimeMemoryFindings},
        {"plugin_matches", advanced.pluginMatches},
        {"confidence_label", advanced.confidenceLabel},
        {"confidence_reason", advanced.confidenceReason},
        {"scheduler_profile", advanced.schedulerProfile},
        {"ml_assessment_label", advanced.mlAssessmentLabel},
        {"ml_assessment_reason", advanced.mlAssessmentReason},
        {"ml_feature_notes", advanced.mlFeatureNotes},
        {"packer_assessment", advanced.packerAssessment},
        {"resource_assessment", advanced.resourceAssessment},
        {"user_facing_highlights", advanced.userFacingHighlights},
        {"legitimate_context", advanced.legitimateContext}
    };

    j["ioc_export"] = {
        {"urls", indicators.urls},
        {"domains", indicators.domains},
        {"ips", indicators.ips},
        {"emails", indicators.emails},
        {"file_paths", indicators.filePaths},
        {"registry_keys", indicators.registryKeys},
        {"commands", indicators.suspiciousCommands}
    };

    return j;
}

inline bool SaveJsonReportToPath(const std::string& outputPath, const nlohmann::json& report)
{
    std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
    if (!out)
        return false;
    out << report.dump(2);
    return true;
}
