#pragma once

// pe parsing outputs for structure, entropy, overlay, and packer-oriented signals.
#include <cstdint>
#include <string>
#include <vector>

#include "asm/asm_bridge.h"

// pe-specific findings live here so later engines can reuse them without reparsing.
// tls callback profiling keeps the pre-entry path visible without turning the pe parser into a full disassembler.
struct TlsCallbackProfile
{
    std::uint32_t index = 0;
    std::uint64_t callbackVa = 0;
    std::uint32_t callbackRva = 0;
    std::uint32_t fileOffset = 0;
    std::string byteWindow;
    std::string startSummary;
    bl::asmbridge::AsmEntrypointProfile profile;
    std::vector<std::string> notes;
    bool redirectsEarly = false;
    bool preEntryLoader = false;
    bool preEntryResolver = false;
    bool preEntryChecks = false;
};

struct PEAnalysisResult
{
    bool fileOpened = false;
    bool isPE = false;
    bool is64Bit = false;
    bool hasSuspiciousSections = false;
    bool possiblePackedFile = false;
    bool hasOverlay = false;
    bool hasTlsCallbacks = false;
    bool entryPointOutsideExecutableSection = false;
    bool hasAntiDebugIndicators = false;
    bool hasResourceData = false;
    bool hasSecurityDirectory = false;
    bool hasDebugDirectory = false;
    bool hasRelocations = false;
    bool hasImports = false;
    bool hasExports = false;
    bool hasSuspiciousEntrypointStub = false;
    bool hasEntrypointJumpStub = false;
    bool hasShellcodeLikeEntrypoint = false;
    bool resourceDirectoryParseOk = false;
    bool tlsDirectoryParsed = false;
    bool hasProfiledTlsCallbacks = false;
    bool hasSuspiciousTlsFlow = false;

    unsigned long long overlaySize = 0;
    unsigned int antiDebugIndicatorCount = 0;
    unsigned int resourceEntryCount = 0;
    unsigned int tlsCallbackCount = 0;
    unsigned int profiledTlsCallbackCount = 0;
    unsigned int executableSectionCount = 0;
    unsigned int writableExecutableSectionCount = 0;
    unsigned int highEntropyExecutableSectionCount = 0;
    unsigned int packerScore = 0;

    unsigned int numberOfSections = 0;
    unsigned int entryPoint = 0;
    unsigned int imageSize = 0;
    std::string entryPointSectionName;
    std::string likelyPackerFamily;
    std::string entryPointHeuristic;
    std::string entryPointStartSummary;
    std::string entryPointBytes;
    bl::asmbridge::AsmEntrypointProfile asmEntrypointProfile;
    std::string asmEntrypointProfileSummary;
    std::string asmCodeSurfaceSummary;
    std::string asmOpcodeFamilySummary;
    std::string tlsProfileSummary;
    std::string overlayProfileSummary;

    unsigned int asmSuspiciousOpcodeScore = 0;
    unsigned int asmBranchOpcodeCount = 0;
    unsigned int asmMemoryAccessPatternCount = 0;
    unsigned int asmRetOpcodeCount = 0;
    unsigned int asmNopOpcodeCount = 0;
    unsigned int asmInt3OpcodeCount = 0;
    unsigned int asmStackFrameHintCount = 0;
    unsigned int asmRipRelativeHintCount = 0;
    unsigned int asmControlTransferCount = 0;
    unsigned int asmStackOperationCount = 0;
    unsigned int asmMemoryTouchCount = 0;
    unsigned int asmArithmeticLogicCount = 0;
    unsigned int asmCompareTestCount = 0;
    unsigned int asmLoopLikeCount = 0;
    unsigned int asmSyscallInterruptCount = 0;
    unsigned int asmStringInstructionCount = 0;
    unsigned int overlayWindowCount = 0;
    unsigned int overlayCompressedWindowCount = 0;
    unsigned int overlayTextWindowCount = 0;
    unsigned int overlayCodeWindowCount = 0;
    unsigned int overlayEmbeddedHeaderHits = 0;
    unsigned int overlayUrlWindowCount = 0;
    double overlayMaxEntropy = 0.0;

    std::vector<std::string> sectionNames;
    std::vector<std::string> suspiciousIndicators;
    std::vector<std::string> asmFeatureDetails;
    std::vector<std::string> asmSemanticTags;
    std::vector<std::string> tlsFindings;
    std::vector<TlsCallbackProfile> tlsCallbackProfiles;
    std::vector<std::string> overlayFindings;
};

bool IsPotentialPEExtension(const std::string& extension);
PEAnalysisResult AnalyzePEFile(const std::string& filePath);
