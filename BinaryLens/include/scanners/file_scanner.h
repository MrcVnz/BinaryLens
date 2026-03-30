#pragma once

// file metadata, hashing, entropy, and type-detection interfaces for local samples.
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "asm/asm_bridge.h"

// file facts are cached here to avoid re-reading the sample across engines.
struct FileInfo
{
    std::string path;
    std::string name;
    std::string extension;
    std::uint64_t size = 0;
    bool readable = false;
    double entropy = 0.0;
    std::string sha256;

    bool hasMZHeader = false;
    bool isPELike = false;
    bool isZipArchive = false;
    bool isScriptLike = false;
    bool doubleExtensionSuspicious = false;
    bool heavyFileMode = false;

    int zipEntryCount = 0;
    int zipSuspiciousEntryCount = 0;
    std::vector<std::string> zipSuspiciousEntries;
    std::vector<std::string> archiveNotes;
    bool archiveInspectionPerformed = false;
    bool archiveContainsExecutable = false;
    bool archiveContainsScript = false;
    bool archiveContainsShortcut = false;
    bool archiveContainsNestedArchive = false;
    bool archiveContainsSuspiciousDoubleExtension = false;
    bool archiveContainsPathTraversal = false;
    bool archiveContainsHiddenEntries = false;
    bool archiveContainsLureAndExecutablePattern = false;

    int suspiciousStringCount = 0;
    std::vector<std::string> suspiciousStrings;
    std::vector<std::string> extractedIndicators;
    std::string cachedPrintableText;

    bl::asmbridge::LowLevelBufferProfile lowLevelProfile;
    bl::asmbridge::AsciiTokenProfile lowLevelAsciiTokens;
    std::uint32_t dominantByteValue = 0;
    std::uint64_t dominantByteCount = 0;
    std::string lowLevelProfileSummary;
    std::vector<std::string> lowLevelFindings;

    int riskScore = 0;
    std::string verdict;
    std::vector<std::string> reasons;
    bool cancelled = false;
};

using FileScanProgressCallback = std::function<void(const std::string& stage,
                                                    const std::string& detail,
                                                    std::uint64_t processedBytes,
                                                    std::uint64_t totalBytes,
                                                    std::uint64_t chunkIndex,
                                                    std::uint64_t chunkCount)>;

FileInfo AnalyzeFile(const std::string& path, FileScanProgressCallback progressCallback = nullptr);
std::string FormatFileSize(std::uint64_t bytes);
std::string GetEntropyLevel(double entropy);
std::string DetectRealFileType(const std::vector<unsigned char>& data);
std::vector<unsigned char> ReadFileHeaderBytes(const std::string& path, size_t maxBytes);
