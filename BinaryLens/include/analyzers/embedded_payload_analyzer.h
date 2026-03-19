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
    std::size_t embeddedPEOffset = 0;
    std::size_t shellcodeOffset = 0;
    unsigned int score = 0;
    std::vector<std::string> findings;
};

EmbeddedPayloadAnalysisResult AnalyzeEmbeddedPayloads(const std::string& filePath, const FileInfo& info);
