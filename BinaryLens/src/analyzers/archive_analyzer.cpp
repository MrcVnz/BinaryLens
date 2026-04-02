#include "analyzers/archive_analyzer.h"
#include "common/string_utils.h"
#include "core/analysis_control.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <set>
#include <string>
#include <vector>
// archive heuristics for surfacing hidden payload names, nesting, and extension abuse.

// shared helpers for extension normalization, bounded lists, and archive-specific name checks.
namespace
{
    constexpr std::uint32_t kZipCentralDirectorySignature = 0x02014B50u;
    constexpr std::uint32_t kZipEOCDSignature = 0x06054B50u;
    constexpr std::uint64_t kEOCDSearchWindow = 1024ull * 128ull;
    constexpr std::uint64_t kMaxZipCentralDirectoryBytes = 64ull * 1024ull * 1024ull;
    constexpr std::size_t kMaxSuspiciousEntries = 16;

    std::string ToLowerCopy(std::string value)
    {
        return bl::common::ToLowerCopy(std::move(value));
    }


    std::uint16_t ReadLe16(const std::vector<unsigned char>& data, std::size_t offset)
    {
        return static_cast<std::uint16_t>(data[offset]) |
               (static_cast<std::uint16_t>(data[offset + 1]) << 8);
    }

    std::uint32_t ReadLe32(const std::vector<unsigned char>& data, std::size_t offset)
    {
        return static_cast<std::uint32_t>(data[offset]) |
               (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
               (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
               (static_cast<std::uint32_t>(data[offset + 3]) << 24);
    }

    void AddUnique(std::vector<std::string>& items, const std::string& value, std::size_t maxCount)
    {
        bl::common::AddUnique(items, value, maxCount);
    }

    std::string GetExtensionLower(const std::string& path)
    {
        const std::size_t dot = path.find_last_of('.');
        if (dot == std::string::npos)
            return "";
        return ToLowerCopy(path.substr(dot));
    }

    bool ContainsDangerousDoubleExtension(const std::string& fileNameLower)
    {
        static const std::set<std::string> safeLead = {
            ".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf"
        };
        static const std::set<std::string> dangerousTail = {
            ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".dll", ".com", ".hta", ".lnk"
        };

        const std::size_t lastDot = fileNameLower.find_last_of('.');
        if (lastDot == std::string::npos || lastDot == 0)
            return false;

        const std::size_t prevDot = fileNameLower.find_last_of('.', lastDot - 1);
        if (prevDot == std::string::npos)
            return false;

        const std::string ext1 = fileNameLower.substr(prevDot, lastDot - prevDot);
        const std::string ext2 = fileNameLower.substr(lastDot);
        return safeLead.count(ext1) > 0 && dangerousTail.count(ext2) > 0;
    }

    bool LooksExecutableExtension(const std::string& ext)
    {
        static const std::set<std::string> exts = {
            ".exe", ".dll", ".scr", ".com", ".sys", ".msi", ".cpl"
        };
        return exts.count(ext) > 0;
    }

    bool LooksScriptExtension(const std::string& ext)
    {
        static const std::set<std::string> exts = {
            ".js", ".jse", ".vbs", ".vbe", ".ps1", ".cmd", ".bat", ".hta", ".wsf", ".wsh"
        };
        return exts.count(ext) > 0;
    }

    bool LooksNestedArchive(const std::string& ext)
    {
        static const std::set<std::string> exts = {
            ".zip", ".rar", ".7z", ".cab", ".iso", ".jar", ".gz", ".tar"
        };
        return exts.count(ext) > 0;
    }

    bool LooksOfficeDocument(const std::string& ext)
    {
        static const std::set<std::string> exts = {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf"
        };
        return exts.count(ext) > 0;
    }

    // entry-name heuristics that score disguised executables, scriptable content, and nested payloads.
bool AnalyzeEntryName(const std::string& originalName, ArchiveAnalysisResult& result)
    {
        const std::string lower = ToLowerCopy(originalName);
        const std::string ext = GetExtensionLower(lower);

        bool suspicious = false;

        // flag zip-slip style names early before looking at the payload extension.
        if (lower.find("../") != std::string::npos || lower.find("..\\") != std::string::npos || (!lower.empty() && (lower[0] == '/' || lower[0] == '\\')))
        {
            result.containsPathTraversal = true;
            AddUnique(result.notes, "Archive contains path traversal or absolute-path style entries", 8);
            suspicious = true;
        }

        const std::size_t slash = lower.find_last_of("\\/");
        const std::string leaf = slash == std::string::npos ? lower : lower.substr(slash + 1);
        if (!leaf.empty() && leaf[0] == '.')
        {
            result.containsHiddenEntries = true;
            suspicious = true;
        }

        // treat decoy names like invoice.pdf.exe as stronger archive lures.
        if (ContainsDangerousDoubleExtension(lower))
        {
            result.containsSuspiciousDoubleExtension = true;
            AddUnique(result.notes, "Archive contains double-extension payload names", 8);
            suspicious = true;
        }

        if (LooksExecutableExtension(ext))
        {
            result.containsExecutable = true;
            suspicious = true;
        }
        if (LooksScriptExtension(ext))
        {
            result.containsScript = true;
            suspicious = true;
        }
        if (ext == ".lnk")
        {
            result.containsShortcut = true;
            suspicious = true;
        }
        if (LooksNestedArchive(ext))
            result.containsNestedArchive = true;
        if (LooksOfficeDocument(ext))
            result.containsOfficeDocument = true;

        // lure wording matters more when it wraps an executable, script, or shortcut.
        const bool lureWord = lower.find("invoice") != std::string::npos ||
                              lower.find("payment") != std::string::npos ||
                              lower.find("document") != std::string::npos ||
                              lower.find("scan") != std::string::npos ||
                              lower.find("receipt") != std::string::npos ||
                              lower.find("resume") != std::string::npos ||
                              lower.find("password") != std::string::npos;
        if (lureWord && (LooksExecutableExtension(ext) || LooksScriptExtension(ext) || ext == ".lnk" || ContainsDangerousDoubleExtension(lower)))
        {
            result.containsLureAndExecutablePattern = true;
            AddUnique(result.notes, "Archive mixes lure-style filenames with executable or script payloads", 8);
            suspicious = true;
        }

        if (suspicious)
        {
            ++result.suspiciousEntryCount;
            AddUnique(result.suspiciousEntries, originalName, kMaxSuspiciousEntries);
        }

        return suspicious;
    }

    bool LooksArchiveFormatByHeader(const std::vector<unsigned char>& header, const std::string& lowerPath, std::string& formatLabel)
    {
        if (header.size() >= 4 && header[0] == 'P' && header[1] == 'K')
        {
            formatLabel = "ZIP";
            return true;
        }
        if (header.size() >= 6 && header[0] == '7' && header[1] == 'z' && header[2] == 0xBC && header[3] == 0xAF && header[4] == 0x27 && header[5] == 0x1C)
        {
            formatLabel = "7z";
            return true;
        }
        if (header.size() >= 7 && header[0] == 'R' && header[1] == 'a' && header[2] == 'r' && header[3] == '!' && header[4] == 0x1A && header[5] == 0x07)
        {
            formatLabel = "RAR";
            return true;
        }

        if (lowerPath.size() >= 4 && lowerPath.rfind(".zip") == lowerPath.size() - 4) { formatLabel = "ZIP"; return true; }
        if (lowerPath.size() >= 3 && lowerPath.rfind(".7z") == lowerPath.size() - 3) { formatLabel = "7z"; return true; }
        if (lowerPath.size() >= 4 && lowerPath.rfind(".rar") == lowerPath.size() - 4) { formatLabel = "RAR"; return true; }
        if (lowerPath.size() >= 4 && lowerPath.rfind(".iso") == lowerPath.size() - 4) { formatLabel = "ISO"; return true; }
        if (lowerPath.size() >= 4 && lowerPath.rfind(".img") == lowerPath.size() - 4) { formatLabel = "IMG"; return true; }
        return false;
    }

    // fallback scan for file-like strings when the archive format is only partially understood.
void AnalyzeLooseEmbeddedNames(const std::vector<unsigned char>& bytes, ArchiveAnalysisResult& result)
    {
        std::string current;
        const auto flushCurrent = [&]() {
            if (current.size() >= 5 && current.find('.') != std::string::npos)
            {
                AnalyzeEntryName(current, result);
                ++result.entryCount;
            }
            current.clear();
        };

        for (unsigned char ch : bytes)
        {
            if ((ch >= 32 && ch <= 126) || ch == '/' || ch == '\\')
            {
                current.push_back(static_cast<char>(ch));
                if (current.size() > 220)
                    flushCurrent();
            }
            else
            {
                flushCurrent();
            }
        }
        flushCurrent();
    }

    bool LooksIsoLike(const std::string& path, std::ifstream& file, std::uint64_t size)
    {
        if (size < 0x9006)
            return false;

        std::vector<unsigned char> sector(16);
        file.seekg(0x8001, std::ios::beg);
        file.read(reinterpret_cast<char*>(sector.data()), 5);
        if (file.gcount() == 5 && std::string(reinterpret_cast<const char*>(sector.data()), 5) == "CD001")
            return true;

        file.clear();
        const std::string lowerPath = ToLowerCopy(path);
        return lowerPath.size() >= 4 && (lowerPath.rfind(".iso") == lowerPath.size() - 4 || lowerPath.rfind(".img") == lowerPath.size() - 4);
    }

}

// main archive pass that selects the parsing strategy and consolidates suspicious findings.
ArchiveAnalysisResult AnalyzeArchiveFile(const std::string& path, std::uint64_t sizeHint)
{
    ArchiveAnalysisResult result;
    result.analyzed = true;

    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        AddUnique(result.notes, "Archive file could not be opened for deep inspection", 8);
        return result;
    }

    file.seekg(0, std::ios::end);
    const std::uint64_t size = sizeHint > 0 ? sizeHint : static_cast<std::uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> header(static_cast<std::size_t>(std::min<std::uint64_t>(size, 128ull)));
    file.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    header.resize(static_cast<std::size_t>(file.gcount()));
    const std::string lowerPath = ToLowerCopy(path);
    LooksArchiveFormatByHeader(header, lowerPath, result.formatLabel);

    // rar, 7z, iso, and img use heuristic name carving because deep structural parsing is format-specific.
    if (result.formatLabel == "RAR" || result.formatLabel == "7z" || result.formatLabel == "ISO" || result.formatLabel == "IMG" || LooksIsoLike(path, file, size))
    {
        if (result.formatLabel.empty())
            result.formatLabel = LooksIsoLike(path, file, size) ? "ISO" : result.formatLabel;
        result.formatSupported = true;
        file.clear();
        file.seekg(0, std::ios::beg);
        const std::size_t probeSize = static_cast<std::size_t>(std::min<std::uint64_t>(size, 4ull * 1024ull * 1024ull));
        std::vector<unsigned char> bytes(probeSize);
        file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        bytes.resize(static_cast<std::size_t>(file.gcount()));
        AnalyzeLooseEmbeddedNames(bytes, result);
        AddUnique(result.notes, result.formatLabel + " deep inspection uses heuristic embedded entry-name extraction", 8);
        if (result.containsExecutable)
            AddUnique(result.notes, "Archive contains executable payloads", 8);
        if (result.containsScript)
            AddUnique(result.notes, "Archive contains script-capable payloads", 8);
        if (result.containsShortcut)
            AddUnique(result.notes, "Archive contains Windows shortcut (.lnk) payloads", 8);
        if (result.containsNestedArchive)
            AddUnique(result.notes, "Archive contains nested archive content", 8);
        return result;
    }

    if (size < 22)
    {
        AddUnique(result.notes, "Archive is too small for ZIP central directory parsing", 8);
        return result;
    }

    const std::uint64_t window = std::min<std::uint64_t>(size, kEOCDSearchWindow);
    file.seekg(static_cast<std::streamoff>(size - window), std::ios::beg);
    std::vector<unsigned char> tail(static_cast<std::size_t>(window));
    file.read(reinterpret_cast<char*>(tail.data()), static_cast<std::streamsize>(tail.size()));
    tail.resize(static_cast<std::size_t>(file.gcount()));
    if (tail.size() < 22)
        return result;

    // scan backwards so zip comments do not hide the eocd marker.
    std::size_t eocdOffset = std::string::npos;
    for (std::size_t i = tail.size() - 22; ; --i)
    {
        if (ReadLe32(tail, i) == kZipEOCDSignature)
        {
            eocdOffset = i;
            break;
        }
        if (i == 0)
            break;
    }

    if (eocdOffset == std::string::npos)
    {
        AddUnique(result.notes, "Deep archive inspection currently supports standard ZIP central directories", 8);
        return result;
    }

    result.formatSupported = true;
    if (result.formatLabel.empty())
        result.formatLabel = "ZIP";

    // trust the central directory more than local headers for a quick archive inventory.
    const std::uint16_t totalEntries = ReadLe16(tail, eocdOffset + 10);
    const std::uint32_t centralDirectorySize = ReadLe32(tail, eocdOffset + 12);
    const std::uint32_t centralDirectoryOffset = ReadLe32(tail, eocdOffset + 16);

    if (centralDirectorySize == 0)
    {
        AddUnique(result.notes, "ZIP central directory is empty", 8);
        return result;
    }

    // zip64 uses sentinel values here, so fall back to bounded heuristics instead of trusting wrapped offsets.
    if (totalEntries == 0xFFFFu || centralDirectorySize == 0xFFFFFFFFu || centralDirectoryOffset == 0xFFFFFFFFu)
    {
        AddUnique(result.notes, "ZIP64 central directory uses extended fields; falling back to heuristic archive name carving", 8);
        file.clear();
        file.seekg(0, std::ios::beg);
        const std::size_t probeSize = static_cast<std::size_t>(std::min<std::uint64_t>(size, 4ull * 1024ull * 1024ull));
        std::vector<unsigned char> bytes(probeSize);
        file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        bytes.resize(static_cast<std::size_t>(file.gcount()));
        AnalyzeLooseEmbeddedNames(bytes, result);
        return result;
    }

    if (centralDirectorySize > size || centralDirectorySize > kMaxZipCentralDirectoryBytes)
    {
        AddUnique(result.notes, "ZIP central directory size is outside the supported safety window", 8);
        return result;
    }

    const std::uint64_t directoryEnd = static_cast<std::uint64_t>(centralDirectoryOffset) + static_cast<std::uint64_t>(centralDirectorySize);
    if (centralDirectoryOffset > size || directoryEnd < centralDirectoryOffset || directoryEnd > size)
    {
        AddUnique(result.notes, "ZIP central directory points outside the archive bounds", 8);
        return result;
    }

    file.seekg(static_cast<std::streamoff>(centralDirectoryOffset), std::ios::beg);
    std::vector<unsigned char> directory(static_cast<std::size_t>(centralDirectorySize));
    file.read(reinterpret_cast<char*>(directory.data()), static_cast<std::streamsize>(directory.size()));
    directory.resize(static_cast<std::size_t>(file.gcount()));
    if (directory.size() < 46)
    {
        AddUnique(result.notes, "ZIP central directory could not be read completely", 8);
        return result;
    }

    std::size_t offset = 0;
    int parsedEntries = 0;
    // walk each central-directory record and only keep payload-looking entries.
    while (offset + 46 <= directory.size())
    {
        if (IsAnalysisCancellationRequested())
        {
            result.cancelled = true;
            break;
        }

        if (ReadLe32(directory, offset) != kZipCentralDirectorySignature)
            break;

        const std::uint16_t fileNameLength = ReadLe16(directory, offset + 28);
        const std::uint16_t extraLength = ReadLe16(directory, offset + 30);
        const std::uint16_t commentLength = ReadLe16(directory, offset + 32);
        const std::size_t recordLength = 46u + fileNameLength + extraLength + commentLength;
        if (offset + recordLength > directory.size())
            break;

        const char* fileNamePtr = reinterpret_cast<const char*>(directory.data() + offset + 46);
        std::string entryName(fileNamePtr, fileNamePtr + fileNameLength);
        // skip pure folder records because they add noise but no payload signal.
        if (!entryName.empty() && entryName.back() != '/' && entryName.back() != '\\')
            AnalyzeEntryName(entryName, result);

        ++parsedEntries;
        offset += recordLength;
    }

    result.entryCount = parsedEntries > 0 ? parsedEntries : totalEntries;

    if (result.containsExecutable)
        AddUnique(result.notes, "Archive contains executable payloads", 8);
    if (result.containsScript)
        AddUnique(result.notes, "Archive contains script-capable payloads", 8);
    if (result.containsShortcut)
        AddUnique(result.notes, "Archive contains Windows shortcut (.lnk) payloads", 8);
    if (result.containsNestedArchive)
        AddUnique(result.notes, "Archive contains nested archive content", 8);
    if (result.containsOfficeDocument && (result.containsExecutable || result.containsScript || result.containsShortcut))
        AddUnique(result.notes, "Archive mixes decoy-style office content with active payload-capable entries", 8);
    if (result.entryCount > 0 && result.suspiciousEntryCount > 0)
    {
        const int suspiciousPct = static_cast<int>((static_cast<double>(result.suspiciousEntryCount) * 100.0) / static_cast<double>(result.entryCount));
        if (suspiciousPct >= 20)
            AddUnique(result.notes, "Archive has a high suspicious-entry density relative to total visible entries", 8);
    }

    return result;
}
