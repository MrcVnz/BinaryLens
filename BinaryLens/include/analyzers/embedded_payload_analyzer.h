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
    bool validatedEmbeddedPE = false;
    bool foundShellcodeLikeBlob = false;
    bool foundExecutableArchiveLure = false;
    bool usedNativeAsmBackend = false;
    bool likelyCompressedNoise = false;
    bool strongCorroboration = false;
    std::size_t embeddedPEOffset = 0;
    std::size_t shellcodeOffset = 0;
    std::size_t strongestProfileOffset = 0;
    unsigned int score = 0;
    unsigned int suspiciousWindowCount = 0;
    unsigned int compressedLikeWindowCount = 0;
    unsigned int corroboratedWindowCount = 0;
    unsigned int validatedPeCandidateCount = 0;
    unsigned int strongestOpcodeScore = 0;
    unsigned int strongestBranchOpcodeCount = 0;
    unsigned int strongestMemoryAccessPatternCount = 0;
    double strongestWindowPrintableRatio = 0.0;
    double strongestWindowHighBitRatio = 0.0;
    double strongestWindowZeroByteRatio = 0.0;
    double strongestWindowOpcodeLeadRatio = 0.0;
    std::string signalReliability = "Low";
    std::string strongestProfileSummary;
    std::vector<std::string> findings;
    std::vector<std::string> strongestProfileDetails;
    std::vector<std::string> maskedPatternFindings;
    std::vector<std::string> contextNotes;
};

EmbeddedPayloadAnalysisResult AnalyzeEmbeddedPayloads(const std::string& filePath, const FileInfo& info);
