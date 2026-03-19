#include "scanners/file_scanner.h"
#include "analyzers/archive_analyzer.h"
#include "core/analysis_control.h"
#include "core/risk_engine.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <set>
#include <sstream>
#include <thread>
// file acquisition, chunked hashing, entropy sampling, and basic artifact extraction.

// file-system helpers, chunked hashing state, and quick heuristics shared by the scanner.
namespace
{
    constexpr std::uint64_t kHeavyFileThreshold = 512ull * 1024ull * 1024ull;
    constexpr std::size_t kChunkSize = 4u * 1024u * 1024u;
    constexpr std::size_t kMaxIndicators = 12;
    constexpr std::size_t kMaxCachedPrintableBytes = 128u * 1024u;

    std::size_t GetAdaptiveChunkSize()
    {
        const unsigned int hw = std::max(1u, std::thread::hardware_concurrency());
        if (hw >= 16)
            return 16u * 1024u * 1024u;
        if (hw >= 8)
            return 8u * 1024u * 1024u;
        if (hw >= 4)
            return 4u * 1024u * 1024u;
        return 2u * 1024u * 1024u;
    }

    std::string ToLowerCopy(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    std::string GetFileNameOnly(const std::string& path)
    {
        const size_t pos = path.find_last_of("\\/");
        return (pos == std::string::npos) ? path : path.substr(pos + 1);
    }

    std::string GetExtensionLower(const std::string& name)
    {
        const size_t pos = name.find_last_of('.');
        if (pos == std::string::npos)
            return "";
        return ToLowerCopy(name.substr(pos));
    }

    void AddUnique(std::vector<std::string>& items, const std::string& value, std::size_t maxCount)
    {
        if (value.empty() || items.size() >= maxCount)
            return;
        if (std::find(items.begin(), items.end(), value) == items.end())
            items.push_back(value);
    }

    bool StartsWithBytes(const std::vector<unsigned char>& data, std::initializer_list<unsigned char> bytes)
    {
        if (data.size() < bytes.size())
            return false;

        std::size_t i = 0;
        for (unsigned char b : bytes)
        {
            if (data[i++] != b)
                return false;
        }
        return true;
    }

    bool ContainsDangerousDoubleExtension(const std::string& fileNameLower)
    {
        static const std::set<std::string> safeLead = {
            ".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx", ".xls", ".xlsx", ".mp3", ".mp4"
        };
        static const std::set<std::string> dangerousTail = {
            ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".dll", ".com", ".hta"
        };

        const size_t lastDot = fileNameLower.find_last_of('.');
        if (lastDot == std::string::npos || lastDot == 0)
            return false;

        const size_t prevDot = fileNameLower.find_last_of('.', lastDot - 1);
        if (prevDot == std::string::npos)
            return false;

        const std::string ext1 = fileNameLower.substr(prevDot, lastDot - prevDot);
        const std::string ext2 = fileNameLower.substr(lastDot);
        return safeLead.count(ext1) > 0 && dangerousTail.count(ext2) > 0;
    }

    void ReportProgress(const FileScanProgressCallback& cb,
                        const std::string& stage,
                        const std::string& detail,
                        std::uint64_t processedBytes,
                        std::uint64_t totalBytes,
                        std::uint64_t chunkIndex,
                        std::uint64_t chunkCount)
    {
        if (cb)
            cb(stage, detail, processedBytes, totalBytes, chunkIndex, chunkCount);
    }

    struct HashContext
    {
        HCRYPTPROV provider = 0;
        HCRYPTHASH hash = 0;
        bool ready = false;

        ~HashContext()
        {
            if (hash)
                CryptDestroyHash(hash);
            if (provider)
                CryptReleaseContext(provider, 0);
        }
    };

    bool BeginSHA256(HashContext& ctx)
    {
        if (!CryptAcquireContextA(&ctx.provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            return false;
        if (!CryptCreateHash(ctx.provider, CALG_SHA_256, 0, 0, &ctx.hash))
            return false;
        ctx.ready = true;
        return true;
    }

    bool UpdateSHA256(HashContext& ctx, const unsigned char* data, DWORD size)
    {
        if (!ctx.ready)
            return false;
        if (size == 0)
            return true;
        return CryptHashData(ctx.hash, data, size, 0) == TRUE;
    }

    std::string FinishSHA256(HashContext& ctx)
    {
        if (!ctx.ready)
            return "";

        BYTE hashValue[32] = {};
        DWORD hashLen = sizeof(hashValue);
        if (!CryptGetHashParam(ctx.hash, HP_HASHVAL, hashValue, &hashLen, 0))
            return "";

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < hashLen; ++i)
            oss << std::setw(2) << static_cast<int>(hashValue[i]);
        return oss.str();
    }

    // folds noteworthy strings from sampled content back into the file metadata summary.
void ProcessCandidateString(const std::string& value, FileInfo& info)
    {
        if (value.size() < 6)
            return;

        bool hasAlphaNum = false;
        for (char c : value)
        {
            if (std::isalnum(static_cast<unsigned char>(c)))
            {
                hasAlphaNum = true;
                break;
            }
        }
        if (!hasAlphaNum)
            return;

        const std::string lower = ToLowerCopy(value);

        if (lower.find("http://") != std::string::npos || lower.find("https://") != std::string::npos)
            AddUnique(info.extractedIndicators, value, kMaxIndicators);
        else if (lower.find("hkcu\\") != std::string::npos || lower.find("hklm\\") != std::string::npos)
            AddUnique(info.extractedIndicators, value, kMaxIndicators);
        else if (lower.find(".onion") != std::string::npos)
            AddUnique(info.extractedIndicators, value, kMaxIndicators);

        struct Pattern { const char* token; const char* label; };
        static const Pattern patterns[] = {
            { "powershell", "PowerShell command indicator" },
            { "powershell.exe", "PowerShell executable reference" },
            { "cmd.exe", "cmd.exe execution indicator" },
            { "rundll32", "rundll32 execution indicator" },
            { "reg add", "Registry modification command" },
            { "schtasks", "Scheduled task command indicator" },
            { "startup", "Startup persistence indicator" },
            { "currentversion\\run", "Run key persistence indicator" },
            { "virtualalloc", "Memory allocation API string" },
            { "writeprocessmemory", "Process memory writing string" },
            { "createremotethread", "Remote thread creation string" },
            { "isdebuggerpresent", "Anti-analysis debugger check" },
            { "urldownloadtofile", "Download-and-execute indicator" },
            { "invoke-webrequest", "PowerShell web request indicator" },
            { "vssadmin delete shadows", "Ransomware shadow-copy tampering indicator" },
            { "wbadmin delete catalog", "Backup catalog deletion indicator" },
            { "bcdedit /set", "Boot configuration tampering indicator" },
            { "keylogger", "Potential spyware / keylogger indicator" },
            { "cookies.sqlite", "Credential theft browser artifact reference" },
            { "login data", "Credential theft browser database reference" }
        };

        for (const auto& pattern : patterns)
        {
            if (lower.find(pattern.token) != std::string::npos)
                AddUnique(info.suspiciousStrings, pattern.label, kMaxIndicators);
        }
    }

    // converts raw file traits into an initial baseline score before deeper engines run.
void FinalizeRisk(FileInfo& info)
    {
        RiskAccumulator risk;

        if (!info.readable)
            risk.Add(20, "File could not be read completely");

        // file type by itself is only light context and should not heavily bias the baseline.
        if (info.isPELike)
            risk.Add(2, "Portable executable structure detected");
        else if (info.isScriptLike)
            risk.Add(4, "Script-capable file type detected");
        else if (info.isZipArchive)
            risk.Add(2, "Archive file detected");

        if (info.doubleExtensionSuspicious)
            risk.Add(30, "Suspicious double extension pattern detected");

        // entropy is useful, but many installers, archives, and compressed payloads are legitimately high entropy.
        if (info.entropy >= 7.7)
            risk.Add(info.isPELike ? 10 : 6, info.isPELike ? "High entropy may indicate packing or compression" : "High entropy detected");
        else if (info.isPELike && info.entropy >= 7.2)
            risk.Add(5, "Moderately high entropy detected in executable");

        // string-only signals are noisy, so keep their baseline influence conservative.
        if (info.suspiciousStringCount >= 4)
            risk.Add(12, "Multiple suspicious strings were found inside the file");
        else if (info.suspiciousStringCount > 0)
            risk.Add(5, "Suspicious strings were found inside the file");

        if (info.archiveInspectionPerformed)
        {
            if (info.archiveContainsExecutable)
                risk.Add(26, "Archive contains executable payloads");
            if (info.archiveContainsScript)
                risk.Add(22, "Archive contains script-capable payloads");
            if (info.archiveContainsShortcut)
                risk.Add(18, "Archive contains Windows shortcut payloads");
            if (info.archiveContainsNestedArchive)
                risk.Add(8, "Archive contains nested archive content");
            if (info.archiveContainsSuspiciousDoubleExtension)
                risk.Add(24, "Archive contains suspicious double-extension payload names");
            if (info.archiveContainsPathTraversal)
                risk.Add(20, "Archive contains path traversal style entries");
            if (info.archiveContainsHiddenEntries)
                risk.Add(6, "Archive contains hidden-style entries");
            if (info.archiveContainsLureAndExecutablePattern)
                risk.Add(18, "Archive combines lure-style filenames with executable content");
            if (info.zipSuspiciousEntryCount >= 4)
                risk.Add(10, "Archive contains multiple suspicious internal entries");
            else if (info.zipSuspiciousEntryCount > 0)
                risk.Add(4, "Archive contains suspicious internal entries");
        }

        if (info.heavyFileMode)
            risk.Add(0, "Heavy file mode used optimized streaming analysis");

        risk.Clamp();
        info.riskScore = risk.Score();
        info.reasons = risk.Reasons();

        const int score = info.riskScore;
        if (score >= 85)
            info.verdict = "Highly Suspicious";
        else if (score >= 60)
            info.verdict = "Suspicious";
        else if (score >= 35)
            info.verdict = "Low Confidence";
        else if (score >= 15)
            info.verdict = "Low Risk";
        else
            info.verdict = "Likely Benign";
    }
}

std::vector<unsigned char> ReadFileHeaderBytes(const std::string& path, size_t maxBytes)
{
    std::vector<unsigned char> data;
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return data;

    data.resize(maxBytes);
    file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(maxBytes));
    data.resize(static_cast<size_t>(file.gcount()));
    return data;
}

std::string DetectRealFileType(const std::vector<unsigned char>& data)
{
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z')
        return "Portable Executable (PE)";
    if (data.size() >= 4)
    {
        if (data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04)
            return "ZIP archive";
        if (data[0] == 'R' && data[1] == 'a' && data[2] == 'r' && data[3] == '!')
            return "RAR archive";
    }
    if (data.size() >= 5 && data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F' && data[4] == '-')
        return "PDF document";
    if (data.size() >= 8 && data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G')
        return "PNG image";
    if (data.size() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
        return "JPEG image";
    if (data.size() >= 2 && data[0] == 0x1F && data[1] == 0x8B)
        return "GZIP archive";
    return "Unknown / generic";
}

// main file scan path that gathers metadata, hashes, entropy, and sampled textual artifacts.
FileInfo AnalyzeFile(const std::string& path, FileScanProgressCallback progressCallback)
{
    FileInfo info;
    info.path = path;
    info.name = GetFileNameOnly(path);
    info.extension = GetExtensionLower(info.name);
    info.doubleExtensionSuspicious = ContainsDangerousDoubleExtension(ToLowerCopy(info.name));

    static const std::set<std::string> scriptLike = {
        ".bat", ".cmd", ".ps1", ".js", ".vbs", ".wsf", ".hta"
    };
    info.isScriptLike = scriptLike.count(info.extension) > 0;

    ReportProgress(progressCallback, "Reading file header and metadata", "Collecting size, extension, and header bytes", 0, 0, 0, 0);

    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fad))
    {
        ULARGE_INTEGER fileSize = {};
        fileSize.HighPart = fad.nFileSizeHigh;
        fileSize.LowPart = fad.nFileSizeLow;
        info.size = fileSize.QuadPart;
    }

    info.heavyFileMode = info.size >= kHeavyFileThreshold;

    const std::vector<unsigned char> header = ReadFileHeaderBytes(path, 4096);
    info.hasMZHeader = StartsWithBytes(header, { 'M', 'Z' });
    info.isPELike = info.hasMZHeader;
    info.isZipArchive = StartsWithBytes(header, { 'P', 'K', 0x03, 0x04 }) || info.extension == ".zip";

    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        FinalizeRisk(info);
        return info;
    }

    HashContext hashCtx;
    BeginSHA256(hashCtx);

    std::array<std::uint64_t, 256> counts = {};
    const std::size_t adaptiveChunkSize = GetAdaptiveChunkSize();
    std::vector<unsigned char> buffer(adaptiveChunkSize);
    std::string currentAscii;
    currentAscii.reserve(256);
    std::uint64_t processed = 0;

    const std::uint64_t chunkCount = info.size == 0 ? 0 : (info.size + adaptiveChunkSize - 1) / adaptiveChunkSize;

    ReportProgress(progressCallback,
                   info.heavyFileMode ? "Preparing heavy file streaming pipeline" : "Preparing streamed scan pipeline",
                   info.heavyFileMode ? "Heavy File Mode active (512 MB+): full scan by streamed chunks" : "Initializing chunked hash, entropy, and string extraction",
                   0,
                   info.size,
                   0,
                   chunkCount);

    std::uint64_t currentChunk = 0;
    while (file)
    {
        if (IsAnalysisCancellationRequested())
        {
            info.cancelled = true;
            break;
        }

        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = file.gcount();
        if (got <= 0)
            break;

        ++currentChunk;
        info.readable = true;
        processed += static_cast<std::uint64_t>(got);
        UpdateSHA256(hashCtx, buffer.data(), static_cast<DWORD>(got));

        for (std::streamsize i = 0; i < got; ++i)
        {
            const unsigned char b = buffer[static_cast<std::size_t>(i)];
            counts[b]++;

            if (info.cachedPrintableText.size() < kMaxCachedPrintableBytes)
            {
                if (b >= 9 && b <= 126)
                    info.cachedPrintableText.push_back(static_cast<char>(b));
                else if (!info.cachedPrintableText.empty() && info.cachedPrintableText.back() != '\n')
                    info.cachedPrintableText.push_back('\n');
            }

            if (b >= 32 && b <= 126)
            {
                currentAscii.push_back(static_cast<char>(b));
                if (currentAscii.size() > 4096)
                {
                    ProcessCandidateString(currentAscii, info);
                    currentAscii.clear();
                }
            }
            else
            {
                ProcessCandidateString(currentAscii, info);
                currentAscii.clear();
            }
        }

        ReportProgress(progressCallback,
                       "Streaming core scan",
                       info.heavyFileMode ? "Executing SHA-256, entropy accumulation, and printable string extraction on current chunk" : "Calculating SHA-256, entropy, and printable strings",
                       processed,
                       info.size,
                       currentChunk,
                       chunkCount);
    }

    ProcessCandidateString(currentAscii, info);
    info.sha256 = FinishSHA256(hashCtx);

    if (processed > 0)
    {
        double entropy = 0.0;
        const double total = static_cast<double>(processed);
        for (std::uint64_t count : counts)
        {
            if (count == 0)
                continue;
            const double p = static_cast<double>(count) / total;
            entropy -= p * std::log2(p);
        }
        info.entropy = entropy;
    }

    info.suspiciousStringCount = static_cast<int>(info.suspiciousStrings.size());

    if (!info.cancelled && info.isZipArchive)
    {
        const ArchiveAnalysisResult archiveResult = AnalyzeArchiveFile(path, info.size);
        info.archiveInspectionPerformed = archiveResult.analyzed;
        info.zipEntryCount = archiveResult.entryCount;
        info.zipSuspiciousEntryCount = archiveResult.suspiciousEntryCount;
        info.zipSuspiciousEntries = archiveResult.suspiciousEntries;
        info.archiveNotes = archiveResult.notes;
        info.archiveContainsExecutable = archiveResult.containsExecutable;
        info.archiveContainsScript = archiveResult.containsScript;
        info.archiveContainsShortcut = archiveResult.containsShortcut;
        info.archiveContainsNestedArchive = archiveResult.containsNestedArchive;
        info.archiveContainsSuspiciousDoubleExtension = archiveResult.containsSuspiciousDoubleExtension;
        info.archiveContainsPathTraversal = archiveResult.containsPathTraversal;
        info.archiveContainsHiddenEntries = archiveResult.containsHiddenEntries;
        info.archiveContainsLureAndExecutablePattern = archiveResult.containsLureAndExecutablePattern;
    }

    ReportProgress(progressCallback,
                   info.cancelled ? "Cancelling analysis" : "Finalizing streamed file scan results",
                   info.cancelled ? "Cancellation requested. Finalizing partial scan state safely" : "Closing streaming hash context and finalizing entropy / string findings",
                   processed,
                   info.size,
                   currentChunk,
                   chunkCount);

    FinalizeRisk(info);
    if (info.cancelled)
    {
        info.verdict = "Cancelled";
        info.reasons.push_back("Analysis was cancelled by the user");
    }
    return info;
}

std::string FormatFileSize(std::uint64_t bytes)
{
    static const char* suffixes[] = { "bytes", "KB", "MB", "GB", "TB" };
    double size = static_cast<double>(bytes);
    int suffixIndex = 0;

    while (size >= 1024.0 && suffixIndex < 4)
    {
        size /= 1024.0;
        ++suffixIndex;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(suffixIndex == 0 ? 0 : 2) << size << ' ' << suffixes[suffixIndex];
    return oss.str();
}

std::string GetEntropyLevel(double entropy)
{
    if (entropy >= 7.5)
        return "High";
    if (entropy >= 6.0)
        return "Medium";
    return "Low";
}
