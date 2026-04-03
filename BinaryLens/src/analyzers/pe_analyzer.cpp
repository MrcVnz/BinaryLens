#include "analyzers/pe_analyzer.h"
#include "common/string_utils.h"

#include <windows.h>
#include <winnt.h>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <vector>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <unordered_set>

#include "asm/asm_bridge.h"
#include "core/low_level_semantics.h"
// portable executable inspection covering structure, entropy, overlays, and packer clues.

// pe helper routines for entropy math, packer hints, and entrypoint byte inspection.
namespace
{
    std::string TrimSectionName(const char name[8])
    {
        std::string result;
        for (int i = 0; i < 8; ++i)
        {
            if (name[i] == '\0')
                break;
            result += name[i];
        }
        return result;
    }

    std::string ToLowerCopy(const std::string& s)
    {
        return bl::common::ToLowerCopy(s);
    }

    // use shannon entropy as a light packing signal, not a verdict on its own.
    double CalculateEntropy(const std::vector<unsigned char>& data)
    {
        if (data.empty())
            return 0.0;

        int freq[256] = { 0 };
        for (unsigned char b : data)
            freq[b]++;

        double entropy = 0.0;
        const double size = static_cast<double>(data.size());

        for (int i = 0; i < 256; ++i)
        {
            if (freq[i] == 0)
                continue;

            const double p = static_cast<double>(freq[i]) / size;
            entropy -= p * std::log2(p);
        }

        return entropy;
    }

    bool IsLikelyPackedSectionName(const std::string& lowerName)
    {
        return lowerName == ".upx0" || lowerName == ".upx1" ||
               lowerName == "upx0" || lowerName == "upx1" ||
               lowerName == ".aspack" || lowerName == "aspack" ||
               lowerName == ".packed" || lowerName == "packed" ||
               lowerName == ".petite" || lowerName == "petite" ||
               lowerName == ".themida" || lowerName == "themida" ||
               lowerName == ".vmp0" || lowerName == ".vmp1";
    }

    void AddIndicator(PEAnalysisResult& result, const std::string& value)
    {
        if (std::find(result.suspiciousIndicators.begin(), result.suspiciousIndicators.end(), value) ==
            result.suspiciousIndicators.end())
        {
            result.suspiciousIndicators.push_back(value);
        }
    }

    struct SectionMeta
    {
        std::string name;
        DWORD virtualAddress = 0;
        DWORD virtualSize = 0;
        DWORD rawOffset = 0;
        DWORD rawSize = 0;
        DWORD characteristics = 0;
    };

    DWORD RVAToFileOffset(DWORD rva, const std::vector<SectionMeta>& sections)
    {
        for (const auto& section : sections)
        {
            const DWORD span = (section.virtualSize > section.rawSize) ? section.virtualSize : section.rawSize;
            if (rva >= section.virtualAddress && rva < section.virtualAddress + span)
                return section.rawOffset + (rva - section.virtualAddress);
        }
        return 0;
    }

    std::string BytesToHex(const std::vector<unsigned char>& data, std::size_t maxCount = 16)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        const std::size_t count = (data.size() < maxCount) ? data.size() : maxCount;
        for (std::size_t i = 0; i < count; ++i)
        {
            if (i > 0)
                oss << ' ';
            oss << std::setw(2) << static_cast<int>(data[i]);
        }
        return oss.str();
    }

    void AddPackerSignal(PEAnalysisResult& result, const std::string& value, unsigned int scoreBoost, const std::string& family = "")
    {
        AddIndicator(result, value);
        result.packerScore += scoreBoost;
        if (result.likelyPackerFamily.empty() && !family.empty())
            result.likelyPackerFamily = family;
    }

    // recurse carefully through the resource tree and stop on loops or unrealistic fan-out.
    unsigned int CountResourceDirectoryEntriesRecursive(std::ifstream& file,
                                                       std::streamoff baseOffset,
                                                       std::streamoff currentOffset,
                                                       std::streamoff fileSize,
                                                       std::unordered_set<long long>& visited,
                                                       int depth = 0)
    {
        if (depth > 4)
            return 0;
        if (currentOffset < 0 || currentOffset + static_cast<std::streamoff>(sizeof(IMAGE_RESOURCE_DIRECTORY)) > fileSize)
            return 0;

        const long long visitKey = static_cast<long long>(currentOffset);
        if (!visited.insert(visitKey).second)
            return 0;

        IMAGE_RESOURCE_DIRECTORY dir = {};
        file.clear();
        file.seekg(currentOffset, std::ios::beg);
        if (!file)
            return 0;
        file.read(reinterpret_cast<char*>(&dir), sizeof(dir));
        if (!file)
            return 0;

        const unsigned int directCount = dir.NumberOfIdEntries + dir.NumberOfNamedEntries;
        if (directCount > 512)
            return 0;

        unsigned int total = directCount;
        const std::streamoff entriesOffset = currentOffset + static_cast<std::streamoff>(sizeof(IMAGE_RESOURCE_DIRECTORY));

        for (unsigned int i = 0; i < directCount; ++i)
        {
            const std::streamoff entryOffset = entriesOffset + static_cast<std::streamoff>(i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
            if (entryOffset < 0 || entryOffset + static_cast<std::streamoff>(sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) > fileSize)
                break;

            IMAGE_RESOURCE_DIRECTORY_ENTRY entry = {};
            file.clear();
            file.seekg(entryOffset, std::ios::beg);
            if (!file)
                break;
            file.read(reinterpret_cast<char*>(&entry), sizeof(entry));
            if (!file)
                break;

            if (entry.OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
            {
                const DWORD relativeSubdirOffset = (entry.OffsetToData & 0x7FFFFFFF);
                const std::streamoff subdirOffset = baseOffset + static_cast<std::streamoff>(relativeSubdirOffset);
                if (subdirOffset >= 0 && subdirOffset < fileSize)
                    total += CountResourceDirectoryEntriesRecursive(file, baseOffset, subdirOffset, fileSize, visited, depth + 1);
            }
        }

        return total;
    }

    unsigned int CountResourceDirectoryEntries(std::ifstream& file, std::streamoff offset, std::streamoff fileSize)
    {
        std::unordered_set<long long> visited;
        return CountResourceDirectoryEntriesRecursive(file, offset, offset, fileSize, visited, 0);
    }

    void AnalyzeOverlayRegions(std::ifstream& file,
                               std::streamoff overlayOffset,
                               std::uint64_t overlaySize,
                               PEAnalysisResult& result)
    {
        if (overlayOffset < 0 || overlaySize == 0)
            return;

        constexpr std::size_t kOverlaySampleLimit = 1024u * 1024u;
        const std::size_t bytesToRead = static_cast<std::size_t>((std::min<std::uint64_t>)(overlaySize, kOverlaySampleLimit));
        std::vector<std::uint8_t> overlayBytes(bytesToRead, 0);

        file.clear();
        file.seekg(overlayOffset, std::ios::beg);
        if (!file)
            return;
        file.read(reinterpret_cast<char*>(overlayBytes.data()), static_cast<std::streamsize>(overlayBytes.size()));
        overlayBytes.resize(static_cast<std::size_t>(file.gcount()));
        if (overlayBytes.empty())
            return;

        // keep overlay interpretation in its own helper so overlays can be discussed as regions, not just a byte count.
        const OverlayProfileResult overlayProfile = AnalyzeOverlayBytes(overlayBytes, static_cast<std::uint64_t>(overlayOffset));
        result.overlayProfileSummary = overlayProfile.summary;
        result.overlayWindowCount = overlayProfile.sampledWindows;
        result.overlayCompressedWindowCount = overlayProfile.compressedLikeWindows;
        result.overlayTextWindowCount = overlayProfile.textLikeWindows;
        result.overlayCodeWindowCount = overlayProfile.codeLikeWindows;
        result.overlayEmbeddedHeaderHits = overlayProfile.embeddedHeaderHits;
        result.overlayUrlWindowCount = overlayProfile.urlLikeWindows;
        result.overlayMaxEntropy = overlayProfile.maxEntropy;
        result.overlayFindings = overlayProfile.findings;

        if (overlayProfile.codeLikeWindows > 0)
            AddIndicator(result, "Overlay profile contains code-like execution windows");
        if (overlayProfile.embeddedHeaderHits > 0)
            AddIndicator(result, "Overlay profile surfaced embedded header-style regions");
        if (overlayProfile.urlLikeWindows > 0)
            AddIndicator(result, "Overlay profile surfaced url-bearing regions");
        if (overlayProfile.compressedLikeWindows >= 2)
            AddPackerSignal(result, "Overlay profile contains multiple compressed-like regions", 6, result.likelyPackerFamily.empty() ? "Overlay-packed" : result.likelyPackerFamily);
    }

    // mirror the new entrypoint profile into the legacy fields so older reporting code keeps working during the transition.
    void ApplyEntrypointSignalReport(const bl::asmbridge::AsmEntrypointProfile& signalReport,
                                   PEAnalysisResult& result)
    {
        result.asmEntrypointProfile = signalReport;
        result.asmEntrypointProfileSummary = signalReport.entrySummary;
        result.asmCodeSurfaceSummary = signalReport.codeSurfaceSummary;
        result.asmOpcodeFamilySummary = signalReport.opcodeFamilySummary;
        result.asmSuspiciousOpcodeScore = signalReport.entryProfile.suspiciousOpcodeScore;
        result.asmBranchOpcodeCount = signalReport.entryProfile.branchOpcodeCount;
        result.asmMemoryAccessPatternCount = signalReport.entryProfile.memoryAccessPatternCount;
        result.asmRetOpcodeCount = signalReport.codeSurface.retOpcodeCount;
        result.asmNopOpcodeCount = signalReport.codeSurface.nopOpcodeCount;
        result.asmInt3OpcodeCount = signalReport.codeSurface.int3OpcodeCount;
        result.asmStackFrameHintCount = signalReport.codeSurface.stackFrameHintCount;
        result.asmRipRelativeHintCount = signalReport.codeSurface.ripRelativeHintCount;
        result.asmControlTransferCount = signalReport.opcodeFamilies.controlTransferCount;
        result.asmStackOperationCount = signalReport.opcodeFamilies.stackOperationCount;
        result.asmMemoryTouchCount = signalReport.opcodeFamilies.memoryTouchCount;
        result.asmArithmeticLogicCount = signalReport.opcodeFamilies.arithmeticLogicCount;
        result.asmCompareTestCount = signalReport.opcodeFamilies.compareTestCount;
        result.asmLoopLikeCount = signalReport.opcodeFamilies.loopLikeCount;
        result.asmSyscallInterruptCount = signalReport.opcodeFamilies.syscallInterruptCount;
        result.asmStringInstructionCount = signalReport.opcodeFamilies.stringInstructionCount;
        result.asmSemanticTags = signalReport.tags;

        for (const auto& finding : signalReport.findings)
            bl::common::AddUnique(result.asmFeatureDetails, finding, 18);
        for (const auto& reason : signalReport.notes)
            bl::common::AddUnique(result.asmFeatureDetails, reason, 18);
    }

    // profiles the entrypoint region to surface loader, unpacking, and redirection stubs early.
    void AnalyzeEntrypointBytes(std::ifstream& file, DWORD fileOffset, PEAnalysisResult& result)
    {
        if (fileOffset == 0)
            return;

        std::vector<unsigned char> epBytes(64, 0);
        file.clear();
        file.seekg(fileOffset, std::ios::beg);
        if (!file)
            return;
        file.read(reinterpret_cast<char*>(epBytes.data()), static_cast<std::streamsize>(epBytes.size()));
        epBytes.resize(static_cast<std::size_t>(file.gcount()));
        if (epBytes.empty())
            return;

        // keep the first bytes for the report before running the asm-backed profile.
        result.entryPointBytes = BytesToHex(epBytes, 16);
        const unsigned char first = epBytes[0];
        if (first == 0xE9 || first == 0xEB || first == 0xFF)
        {
            result.hasEntrypointJumpStub = true;
            result.hasSuspiciousEntrypointStub = true;
            result.entryPointHeuristic = "Entrypoint begins with a jump / trampoline stub";
            AddIndicator(result, "Entrypoint starts with a jump stub");
        }
        if (epBytes.size() >= 6 && epBytes[0] == 0x68 && epBytes[5] == 0xC3)
        {
            result.hasSuspiciousEntrypointStub = true;
            if (result.entryPointHeuristic.empty())
                result.entryPointHeuristic = "Entrypoint uses push-ret redirection stub";
            AddIndicator(result, "Entrypoint uses push-ret style redirection stub");
        }
        std::size_t zeroCount = 0;
        for (unsigned char b : epBytes)
            if (b == 0x00 || b == 0x90)
                ++zeroCount;
        if (zeroCount >= 10)
        {
            result.hasShellcodeLikeEntrypoint = true;
            if (result.entryPointHeuristic.empty())
                result.entryPointHeuristic = "Entrypoint bytes look sparse / stub-like";
            AddIndicator(result, "Entrypoint bytes look unusually sparse or padded");
        }

        // the schema-backed report keeps low-level output stable while still mirroring the legacy flat fields.
        const bl::asmbridge::AsmEntrypointProfile signalReport =
            bl::asmbridge::BuildEntrypointProfile(epBytes.data(), epBytes.size(), static_cast<std::uint64_t>(fileOffset));
        ApplyEntrypointSignalReport(signalReport, result);

        const bl::asmbridge::EntrypointAsmProfile& asmProfile = signalReport.entryProfile;
        if (signalReport.suggestsStub)
            result.hasSuspiciousEntrypointStub = true;
        if (bl::asmbridge::HasFeature(asmProfile, bl::asmbridge::stub_initial_jump))
            result.hasEntrypointJumpStub = true;
        if (signalReport.suggestsDecoder || bl::asmbridge::HasFeature(asmProfile, bl::asmbridge::stub_sparse_padding))
            result.hasShellcodeLikeEntrypoint = true;

        if (!signalReport.entrySummary.empty())
        {
            AddIndicator(result, "Entrypoint asm profile: " + signalReport.entrySummary);
            if (result.entryPointHeuristic.empty())
                result.entryPointHeuristic = "Entrypoint asm profile indicates " + signalReport.entrySummary;
        }

        // a few signals still escalate specific indicator lines because analysts often pivot on these exact phrases.
        if (bl::asmbridge::HasFeature(asmProfile, bl::asmbridge::stub_peb_access))
            AddIndicator(result, "Entrypoint references PEB-style access patterns");
        if (bl::asmbridge::HasFeature(asmProfile, bl::asmbridge::stub_syscall_sequence))
            AddIndicator(result, "Entrypoint contains syscall-style opcode sequence");
        if (bl::asmbridge::HasFeature(asmProfile, bl::asmbridge::stub_decoder_loop))
            AddIndicator(result, "Entrypoint contains decoder-like opcode flow");
        if (bl::asmbridge::HasFeature(asmProfile, bl::asmbridge::stub_manual_mapping_hint))
            AddIndicator(result, "Entrypoint shows manual-mapping style memory access hints");
        if (!signalReport.codeSurfaceSummary.empty())
            AddIndicator(result, "Entrypoint code surface profile: " + signalReport.codeSurfaceSummary);
        if (!signalReport.opcodeFamilySummary.empty())
            AddIndicator(result, "Entrypoint opcode-family profile: " + signalReport.opcodeFamilySummary);

        if (signalReport.suggestsLoader && signalReport.suggestsDecoder)
            AddPackerSignal(result, "Entrypoint semantic profile resembles a loader-decoder opening stub", 12, "Loader / unpacker stub");
        else if (signalReport.suggestsLoader || signalReport.suggestsStub)
            AddPackerSignal(result, "Entrypoint semantic profile contains staged-loader traits", 6, "Low-level stub");
        else if (asmProfile.suspiciousOpcodeScore >= 8)
            AddPackerSignal(result, "Entrypoint opcode profile strongly resembles a loader or unpacking stub", 12, "Loader / unpacker stub");
        else if (asmProfile.suspiciousOpcodeScore >= 5)
            AddPackerSignal(result, "Entrypoint opcode profile contains multiple low-level stub indicators", 6, "Low-level stub");
    }

}

bool IsPotentialPEExtension(const std::string& extension)
{
    const std::string ext = ToLowerCopy(extension);
    return ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" || ext == ".ocx" || ext == ".cpl";
}


// full pe walk that validates headers, inspects sections, and records structural anomalies.
PEAnalysisResult AnalyzePEFile(const std::string& filePath)
{
    PEAnalysisResult result;

    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        return result;

    result.fileOpened = true;

    file.seekg(0, std::ios::end);
    const std::streamoff fileSize = file.tellg();
    file.seekg(0, std::ios::beg);


    // bail out fast unless the file looks like a real pe from the first two header stages.
    IMAGE_DOS_HEADER dosHeader = {};
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (!file || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return result;

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    if (!file)
        return result;

    DWORD peSignature = 0;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));
    if (!file || peSignature != IMAGE_NT_SIGNATURE)
        return result;

    result.isPE = true;

    IMAGE_FILE_HEADER fileHeader = {};
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    if (!file)
        return result;

    WORD optionalMagic = 0;
    std::streampos optionalHeaderPos = file.tellg();
    file.read(reinterpret_cast<char*>(&optionalMagic), sizeof(optionalMagic));
    if (!file)
        return result;

    file.seekg(optionalHeaderPos, std::ios::beg);

    DWORD tlsDirectoryRva = 0;
    DWORD tlsDirectorySize = 0;
    DWORD resourceDirectoryRva = 0;
    DWORD resourceDirectorySize = 0;
    DWORD securityDirectoryRva = 0;
    DWORD securityDirectorySize = 0;
    DWORD debugDirectoryRva = 0;
    DWORD debugDirectorySize = 0;
    DWORD relocDirectoryRva = 0;
    DWORD relocDirectorySize = 0;
    DWORD importDirectoryRva = 0;
    DWORD importDirectorySize = 0;
    DWORD exportDirectoryRva = 0;
    DWORD exportDirectorySize = 0;

    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER64 optionalHeader = {};
        file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));
        if (!file)
            return result;

        result.is64Bit = true;
        result.entryPoint = optionalHeader.AddressOfEntryPoint;
        result.imageSize = optionalHeader.SizeOfImage;
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
        {
            tlsDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            tlsDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE)
        {
            resourceDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            resourceDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY)
        {
            securityDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            securityDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
        {
            debugDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debugDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
        {
            relocDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            relocDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
        {
            importDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            importDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            exportDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
    }
    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER32 optionalHeader = {};
        file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));
        if (!file)
            return result;

        result.is64Bit = false;
        result.entryPoint = optionalHeader.AddressOfEntryPoint;
        result.imageSize = optionalHeader.SizeOfImage;
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
        {
            tlsDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            tlsDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE)
        {
            resourceDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            resourceDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY)
        {
            securityDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            securityDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
        {
            debugDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debugDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
        {
            relocDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            relocDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
        {
            importDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            importDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            exportDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
    }
    else
    {
        return result;
    }

    result.numberOfSections = fileHeader.NumberOfSections;

    if (tlsDirectoryRva != 0 && tlsDirectorySize != 0)
    {
        result.hasTlsCallbacks = true;
        AddIndicator(result, "TLS directory present (possible TLS callbacks)");
    }
    result.hasResourceData = (resourceDirectoryRva != 0 && resourceDirectorySize != 0);
    result.hasSecurityDirectory = (securityDirectoryRva != 0 && securityDirectorySize != 0);
    result.hasDebugDirectory = (debugDirectoryRva != 0 && debugDirectorySize != 0);
    result.hasRelocations = (relocDirectoryRva != 0 && relocDirectorySize != 0);
    result.hasImports = (importDirectoryRva != 0 && importDirectorySize != 0);
    result.hasExports = (exportDirectoryRva != 0 && exportDirectorySize != 0);

    if (result.numberOfSections == 0)
    {
        result.hasSuspiciousSections = true;
        AddIndicator(result, "Executable contains zero sections");
        return result;
    }

    if (result.numberOfSections > 10)
    {
        result.hasSuspiciousSections = true;
        AddIndicator(result, "Unusually high number of sections detected");
    }

    std::vector<SectionMeta> sections;
    sections.reserve(fileHeader.NumberOfSections);

    bool entryPointMapped = false;
    bool entryPointInText = false;
    bool entryPointInExecutable = false;
    DWORD lastSectionEnd = 0;
    unsigned int highEntropyExecutableSections = 0;
    unsigned int rwxSections = 0;

    // collect section metadata first so later rva lookups share the same mapping logic.
    for (unsigned int i = 0; i < fileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER sectionHeader = {};
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));
        if (!file)
            break;

        std::string sectionName = TrimSectionName(reinterpret_cast<const char*>(sectionHeader.Name));
        result.sectionNames.push_back(sectionName);

        SectionMeta meta;
        meta.name = sectionName;
        meta.virtualAddress = sectionHeader.VirtualAddress;
        meta.virtualSize = sectionHeader.Misc.VirtualSize;
        meta.rawOffset = sectionHeader.PointerToRawData;
        meta.rawSize = sectionHeader.SizeOfRawData;
        meta.characteristics = sectionHeader.Characteristics;
        sections.push_back(meta);

        const std::string lowerName = ToLowerCopy(sectionName);
        const DWORD characteristics = sectionHeader.Characteristics;
        const bool isExecutable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool isWritable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        if (isExecutable)
            ++result.executableSectionCount;

        if (sectionName.empty())
        {
            result.hasSuspiciousSections = true;
            AddIndicator(result, "Unnamed PE section detected");
        }

        if (IsLikelyPackedSectionName(lowerName))
        {
            result.hasSuspiciousSections = true;
            result.possiblePackedFile = true;
            AddPackerSignal(result, "Known packer-like section name detected: " + sectionName, 18, lowerName.find("upx") != std::string::npos ? "UPX-like" : "Common packer section");
        }

        if (isExecutable && isWritable)
        {
            ++rwxSections;
            ++result.writableExecutableSectionCount;
            result.hasSuspiciousSections = true;
            AddIndicator(result, "RWX section detected: " + sectionName);
        }

        const DWORD sectionSpan = (sectionHeader.Misc.VirtualSize > sectionHeader.SizeOfRawData)
            ? sectionHeader.Misc.VirtualSize
            : sectionHeader.SizeOfRawData;
        if (result.entryPoint >= sectionHeader.VirtualAddress &&
            result.entryPoint < sectionHeader.VirtualAddress + sectionSpan)
        {
            entryPointMapped = true;
            result.entryPointSectionName = sectionName.empty() ? "[unnamed]" : sectionName;
            if (isExecutable)
                entryPointInExecutable = true;
            if (lowerName == ".text" || lowerName == "text")
                entryPointInText = true;
        }

        // section bytes are sampled for entropy and sparse executable regions.
        if (sectionHeader.PointerToRawData > 0 && sectionHeader.SizeOfRawData > 0)
        {
            DWORD sectionEnd = sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData;
            if (sectionEnd > lastSectionEnd)
                lastSectionEnd = sectionEnd;

            std::streampos currentPos = file.tellg();

            file.seekg(sectionHeader.PointerToRawData, std::ios::beg);
            if (!file)
            {
                file.clear();
                file.seekg(currentPos, std::ios::beg);
                continue;
            }

            std::vector<unsigned char> sectionData(sectionHeader.SizeOfRawData);
            file.read(reinterpret_cast<char*>(sectionData.data()), sectionData.size());

            if (file)
            {
                const double sectionEntropy = CalculateEntropy(sectionData);

                if (sectionEntropy >= 7.3)
                {
                    std::ostringstream oss;
                    oss << std::fixed << std::setprecision(2) << sectionEntropy;

                    result.hasSuspiciousSections = true;
                    AddIndicator(result, "High entropy section detected: " + sectionName + " (" + oss.str() + ")");

                    if (isExecutable)
                    {
                        ++highEntropyExecutableSections;
                        ++result.highEntropyExecutableSectionCount;
                    }
                }

                if (sectionData.size() >= 512)
                {
                    size_t zeroCount = 0;
                    for (size_t j = 0; j < sectionData.size(); ++j)
                    {
                        if (sectionData[j] == 0)
                            ++zeroCount;
                    }

                    const double zeroRatio = static_cast<double>(zeroCount) / static_cast<double>(sectionData.size());
                    if (isExecutable && zeroRatio > 0.95)
                    {
                        result.hasSuspiciousSections = true;
                        AddIndicator(result, "Executable section is almost entirely zero-filled: " + sectionName);
                    }
                }
            }

            file.clear();
            file.seekg(currentPos, std::ios::beg);
        }
    }

    // treat odd entrypoint placement as a structure warning even when the file still loads.
    if (!entryPointMapped)
    {
        result.hasSuspiciousSections = true;
        AddIndicator(result, "Entry point does not map to any section");
    }
    else if (!entryPointInExecutable)
    {
        result.entryPointOutsideExecutableSection = true;
        result.hasSuspiciousSections = true;
        AddIndicator(result, "Entry point is outside executable section: " + result.entryPointSectionName);
    }
    else if (!entryPointInText)
    {
        result.hasSuspiciousSections = true;
        AddIndicator(result, "Entry point is outside .text section: " + result.entryPointSectionName);
    }

    if (highEntropyExecutableSections > 0 && result.numberOfSections <= 3)
    {
        result.possiblePackedFile = true;
        AddPackerSignal(result, "High entropy executable section with low section count (possible packed file)", 22, "Packed / compressed");
    }

    if (highEntropyExecutableSections > 0 && rwxSections > 0)
    {
        result.possiblePackedFile = true;
        AddPackerSignal(result, "Combination of RWX and high entropy sections detected", 20, "Loader / unpacker stub");
    }

    // any tail beyond the last mapped section is reported as overlay data.
    if (fileSize > 0 && static_cast<unsigned long long>(fileSize) > lastSectionEnd && lastSectionEnd > 0)
    {
        result.hasOverlay = true;
        result.overlaySize = static_cast<unsigned long long>(fileSize) - lastSectionEnd;

        std::ostringstream oss;
        oss << "Overlay detected (size: " << result.overlaySize << " bytes)";
        AddIndicator(result, oss.str());

        if (result.overlaySize > 1024)
        {
            result.possiblePackedFile = true;
            AddPackerSignal(result, "Large overlay may indicate packed or injected data", 14, "Overlay-packed");
        }

        AnalyzeOverlayRegions(file, static_cast<std::streamoff>(lastSectionEnd), result.overlaySize, result);
    }

    if (result.hasResourceData)
    {
        const DWORD resourceOffset = RVAToFileOffset(resourceDirectoryRva, sections);
        if (resourceOffset != 0)
        {
            result.resourceDirectoryParseOk = true;
            result.resourceEntryCount = CountResourceDirectoryEntries(file, resourceOffset, fileSize);
            AddIndicator(result, "Resource directory present");
            if (result.resourceEntryCount > 32)
                AddIndicator(result, "Large number of resource directory entries detected");
        }
    }

    const DWORD entryPointOffset = RVAToFileOffset(result.entryPoint, sections);
    if (entryPointOffset != 0)
        AnalyzeEntrypointBytes(file, entryPointOffset, result);
    if (result.executableSectionCount == 1 && result.numberOfSections <= 3 && result.hasEntrypointJumpStub)
        AddPackerSignal(result, "Single executable section with jump-stub entrypoint detected", 16, "Stub unpacker");

    {
        // a cheap whole-file string sweep adds anti-debug context without a full disassembly pass.
        static const std::vector<std::string> antiDebugTokens = {
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugString",
            "DebugActiveProcess",
            "NtSetInformationThread",
            "ProcessDebugPort",
            "ProcessDebugFlags",
            "FindWindow",
            "ZwQueryInformationProcess"
        };

        file.clear();
        file.seekg(0, std::ios::beg);
        std::vector<unsigned char> chunk(1024 * 1024);
        std::string carry;
        carry.reserve(256);

        while (file)
        {
            file.read(reinterpret_cast<char*>(chunk.data()), static_cast<std::streamsize>(chunk.size()));
            const std::streamsize got = file.gcount();
            if (got <= 0)
                break;

            std::string content = carry;
            content.append(reinterpret_cast<const char*>(chunk.data()), static_cast<size_t>(got));

            for (const std::string& token : antiDebugTokens)
            {
                if (content.find(token) != std::string::npos)
                {
                    if (std::find(result.suspiciousIndicators.begin(), result.suspiciousIndicators.end(),
                                  "Anti-debug indicator found: " + token) == result.suspiciousIndicators.end())
                    {
                        ++result.antiDebugIndicatorCount;
                        result.hasAntiDebugIndicators = true;
                        AddIndicator(result, "Anti-debug indicator found: " + token);
                    }
                }
            }

            // keep overlap so anti-debug names split across chunk edges still match.
            const size_t keep = 128;
            if (content.size() > keep)
                carry = content.substr(content.size() - keep);
            else
                carry = content;
        }
    }

    if (result.entryPoint == 0)
    {
        result.hasSuspiciousSections = true;
        AddIndicator(result, "Entry point RVA is zero");
    }

    if (result.imageSize == 0)
    {
        result.hasSuspiciousSections = true;
        AddIndicator(result, "PE image size is zero");
    }

    if (result.hasShellcodeLikeEntrypoint && result.entryPointHeuristic.empty())
        result.entryPointHeuristic = "Entrypoint bytes resemble shellcode or unpacking stub";

    if (result.packerScore >= 18)
        result.possiblePackedFile = true;

    if (result.likelyPackerFamily.empty() && result.possiblePackedFile)
        result.likelyPackerFamily = "Generic packed / obfuscated PE";

    return result;
}
