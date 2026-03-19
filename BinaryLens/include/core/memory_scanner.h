#pragma once

// memory-oriented structures for suspicious allocation and injection-style indicators.
#include <string>
#include <vector>

#include "scanners/file_scanner.h"

struct MemoryScannerResult
{
    std::vector<std::string> findings;
    int matchingProcessCount = 0;
};

MemoryScannerResult AnalyzeRuntimeMemoryContext(const FileInfo& info);
