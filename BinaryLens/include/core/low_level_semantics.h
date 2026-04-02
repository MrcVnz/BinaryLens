#pragma once

// low-level semantic summaries that sit between raw opcode counts and user-facing findings.
#include <cstdint>
#include <string>
#include <vector>

#include "asm/asm_bridge.h"

struct OpcodeSemanticSummary
{
    bool branchHeavy = false;
    bool stubLike = false;
    bool resolverLike = false;
    bool decoderLike = false;
    bool loaderLike = false;
    bool stackSetupHeavy = false;
    std::string summary;
    std::vector<std::string> findings;
    std::vector<std::string> tags;
};

struct OverlayProfileResult
{
    bool analyzed = false;
    std::uint32_t sampledWindows = 0;
    std::uint32_t compressedLikeWindows = 0;
    std::uint32_t textLikeWindows = 0;
    std::uint32_t codeLikeWindows = 0;
    std::uint32_t embeddedHeaderHits = 0;
    std::uint32_t urlLikeWindows = 0;
    double maxEntropy = 0.0;
    std::string summary;
    std::vector<std::string> findings;
};

OpcodeSemanticSummary BuildOpcodeSemanticSummary(const bl::asmbridge::EntrypointAsmProfile& entryProfile,
                                                const bl::asmbridge::CodeSurfaceProfile& codeSurface,
                                                const bl::asmbridge::OpcodeFamilyProfile& opcodeFamilies);

OverlayProfileResult AnalyzeOverlayBytes(const std::vector<std::uint8_t>& overlayBytes,
                                         std::uint64_t overlayBaseOffset);
