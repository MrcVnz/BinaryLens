#pragma once

// archive analysis contracts for suspicious container contents and payload naming signals.
#include <cstdint>
#include <string>
#include <vector>

struct ArchiveAnalysisResult
{
    bool analyzed = false;
    bool formatSupported = false;
    bool cancelled = false;
    std::string formatLabel;
    int entryCount = 0;
    int suspiciousEntryCount = 0;
    std::vector<std::string> suspiciousEntries;
    std::vector<std::string> notes;
    bool containsExecutable = false;
    bool containsScript = false;
    bool containsShortcut = false;
    bool containsNestedArchive = false;
    bool containsSuspiciousDoubleExtension = false;
    bool containsPathTraversal = false;
    bool containsHiddenEntries = false;
    bool containsLureAndExecutablePattern = false;
    bool containsOfficeDocument = false;
};

ArchiveAnalysisResult AnalyzeArchiveFile(const std::string& path, std::uint64_t sizeHint = 0);
