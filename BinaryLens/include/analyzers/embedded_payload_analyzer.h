#pragma once

// embedded payload and shellcode-oriented heuristics for non-pe files and mixed-content samples.
#include <cstddef>
#include <string>
#include <vector>

#include "scanners/file_scanner.h"

struct EmbeddedPayloadAnalysisResult
{
    bool analyzed = false;
    bool foundEmbeddedPE = false;
    bool foundShellcodeLikeBlob = false;
    bool foundExecutableArchiveLure = false;
    bool usedNativeAsmBackend = false;
    bool likelyCompressedNoise = false;
    bool payloadCorroborated = false;
    std::size_t embeddedPEOffset = 0;
    std::size_t shellcodeOffset = 0;
    std::size_t strongestProfileOffset = 0;
    unsigned int score = 0;
    unsigned int suspiciousWindowCount = 0;
    unsigned int strongestOpcodeScore = 0;
    unsigned int strongestBranchOpcodeCount = 0;
    unsigned int strongestMemoryAccessPatternCount = 0;
    unsigned int corroborationCount = 0;
    double strongestHighBitRatio = 0.0;
    std::string strongestProfileSummary;
    std::string disposition = "No embedded payload signal";
    std::string signalReliability = "Low";
    std::vector<std::string> findings;
    std::vector<std::string> strongestProfileDetails;
    std::vector<std::string> maskedPatternFindings;
    std::vector<std::string> contextualNotes;
};

EmbeddedPayloadAnalysisResult AnalyzeEmbeddedPayloads(const std::string& filePath, const FileInfo& info);
