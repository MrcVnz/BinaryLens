#include "analyzers/import_analyzer.h"

#include <windows.h>
#include <winnt.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <vector>
// import-table parsing and capability clustering for static behavior inference.

// low-level pe readers used to walk headers, sections, and imported symbol tables safely.
namespace
{
    std::string ToLowerCopy(const std::string& s)
    {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    template <typename T>
    bool ReadStructAt(std::ifstream& file, std::streamoff offset, T& out)
    {
        file.clear();
        file.seekg(offset, std::ios::beg);
        if (!file)
            return false;
        file.read(reinterpret_cast<char*>(&out), sizeof(T));
        return static_cast<bool>(file);
    }

    bool ReadBytesAt(std::ifstream& file, std::streamoff offset, std::vector<unsigned char>& out, size_t size)
    {
        out.assign(size, 0);
        file.clear();
        file.seekg(offset, std::ios::beg);
        if (!file)
            return false;
        file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
        out.resize(static_cast<size_t>(file.gcount()));
        return !out.empty();
    }

    bool ReadCStringAt(std::ifstream& file, std::streamoff offset, std::string& out, size_t maxLen = 512)
    {
        out.clear();
        file.clear();
        file.seekg(offset, std::ios::beg);
        if (!file)
            return false;

        for (size_t i = 0; i < maxLen; ++i)
        {
            char ch = 0;
            file.read(&ch, 1);
            if (!file)
                break;
            if (ch == '\0')
                return true;
            out.push_back(ch);
        }
        return !out.empty();
    }

    struct SectionInfo
    {
        DWORD virtualAddress = 0;
        DWORD virtualSize = 0;
        DWORD rawAddress = 0;
        DWORD rawSize = 0;
    };

    DWORD RVAToFileOffset(DWORD rva, const std::vector<SectionInfo>& sections)
    {
        for (const auto& section : sections)
        {
            const DWORD span = (section.virtualSize > section.rawSize) ? section.virtualSize : section.rawSize;
            if (rva >= section.virtualAddress && rva < section.virtualAddress + span)
                return section.rawAddress + (rva - section.virtualAddress);
        }
        return 0;
    }

    std::set<std::string> BuildSuspiciousImportSet()
    {
        return {
            "writeprocessmemory", "readprocessmemory", "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
            "createremotethread", "ntcreatethreadex", "queueuserapc", "setwindowshookexa", "setwindowshookexw",
            "getasynckeystate", "winexec", "shellexecutea", "shellexecutew", "urldownloadtofilea", "urldownloadtofilew",
            "internetopena", "internetopenw", "internetopenurla", "internetopenurlw", "httpsendrequesta", "httpsendrequestw",
            "wsastartup", "socket", "connect", "recv", "send", "bind", "listen", "accept", "loadlibrarya", "loadlibraryw",
            "getprocaddress", "isdebuggerpresent", "checkremotedebuggerpresent", "createservicea", "createservicew",
            "startservicea", "startservicew", "openprocess", "createtoolhelp32snapshot"
        };
    }

    bool HasImport(const std::vector<std::string>& imports, const std::string& name)
    {
        const std::string target = ToLowerCopy(name);
        for (const auto& value : imports)
        {
            if (ToLowerCopy(value) == target)
                return true;
        }
        return false;
    }

    void AddNoteUnique(std::vector<std::string>& notes, const std::string& note)
    {
        if (std::find(notes.begin(), notes.end(), note) == notes.end())
            notes.push_back(note);
    }

    bool HasAnyImport(const std::vector<std::string>& imports, const std::vector<std::string>& names)
    {
        for (const auto& name : names)
        {
            if (HasImport(imports, name))
                return true;
        }
        return false;
    }

    void AddClusterUnique(std::vector<std::string>& clusters, const std::string& cluster)
    {
        if (std::find(clusters.begin(), clusters.end(), cluster) == clusters.end())
            clusters.push_back(cluster);
    }

}

// maps imported apis into behavioral clusters while keeping generic imports from over-scoring the sample.
ImportAnalysisResult AnalyzePEImports(const std::string& filePath)
{
    ImportAnalysisResult result;

    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        return result;

    result.fileOpened = true;

    IMAGE_DOS_HEADER dosHeader = {};
    if (!ReadStructAt(file, 0, dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return result;

    DWORD signature = 0;
    if (!ReadStructAt(file, dosHeader.e_lfanew, signature) || signature != IMAGE_NT_SIGNATURE)
        return result;

    result.isPE = true;

    IMAGE_FILE_HEADER fileHeader = {};
    if (!ReadStructAt(file, dosHeader.e_lfanew + sizeof(DWORD), fileHeader))
        return result;

    WORD optionalMagic = 0;
    const std::streamoff optionalOffset = dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!ReadStructAt(file, optionalOffset, optionalMagic))
        return result;

    DWORD importRVA = 0;
    DWORD importSize = 0;
    std::vector<SectionInfo> sections;
    sections.reserve(fileHeader.NumberOfSections);

    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER64 optionalHeader = {};
        if (!ReadStructAt(file, optionalOffset, optionalHeader))
            return result;
        importRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER32 optionalHeader = {};
        if (!ReadStructAt(file, optionalOffset, optionalHeader))
            return result;
        importRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
    else
    {
        return result;
    }

    const std::streamoff sectionOffset = optionalOffset + fileHeader.SizeOfOptionalHeader;
    for (unsigned int i = 0; i < fileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER section = {};
        if (!ReadStructAt(file, sectionOffset + static_cast<std::streamoff>(i * sizeof(IMAGE_SECTION_HEADER)), section))
            return result;
        SectionInfo info;
        info.virtualAddress = section.VirtualAddress;
        info.virtualSize = section.Misc.VirtualSize;
        info.rawAddress = section.PointerToRawData;
        info.rawSize = section.SizeOfRawData;
        sections.push_back(info);
    }

    if (importRVA == 0 || importSize == 0)
    {
        AddNoteUnique(result.notes, "PE file has no import table");
        return result;
    }

    const DWORD importOffset = RVAToFileOffset(importRVA, sections);
    if (importOffset == 0)
    {
        AddNoteUnique(result.notes, "Could not resolve import table RVA");
        return result;
    }

    const bool is64Bit = (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    const std::set<std::string> suspiciousSet = BuildSuspiciousImportSet();

    for (size_t index = 0; ; ++index)
    {
        IMAGE_IMPORT_DESCRIPTOR desc = {};
        if (!ReadStructAt(file, importOffset + static_cast<std::streamoff>(index * sizeof(desc)), desc))
            break;
        if (desc.Name == 0 && desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0)
            break;

        const DWORD thunkRVA = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        const DWORD thunkOffset = RVAToFileOffset(thunkRVA, sections);
        if (thunkOffset == 0)
            continue;

        if (is64Bit)
        {
            for (size_t thunkIndex = 0; ; ++thunkIndex)
            {
                IMAGE_THUNK_DATA64 thunk = {};
                if (!ReadStructAt(file, thunkOffset + static_cast<std::streamoff>(thunkIndex * sizeof(thunk)), thunk))
                    break;
                if (thunk.u1.AddressOfData == 0)
                    break;
                if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    continue;

                const DWORD nameOffset = RVAToFileOffset(static_cast<DWORD>(thunk.u1.AddressOfData), sections);
                if (nameOffset == 0)
                    continue;

                WORD hint = 0;
                if (!ReadStructAt(file, nameOffset, hint))
                    continue;

                std::string name;
                if (!ReadCStringAt(file, nameOffset + sizeof(WORD), name))
                    continue;

                result.totalImports++;
                result.allImportedFunctions.push_back(name);
                if (suspiciousSet.count(ToLowerCopy(name)) > 0)
                    result.suspiciousImports.push_back(name);
            }
        }
        else
        {
            for (size_t thunkIndex = 0; ; ++thunkIndex)
            {
                IMAGE_THUNK_DATA32 thunk = {};
                if (!ReadStructAt(file, thunkOffset + static_cast<std::streamoff>(thunkIndex * sizeof(thunk)), thunk))
                    break;
                if (thunk.u1.AddressOfData == 0)
                    break;
                if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                    continue;

                const DWORD nameOffset = RVAToFileOffset(static_cast<DWORD>(thunk.u1.AddressOfData), sections);
                if (nameOffset == 0)
                    continue;

                WORD hint = 0;
                if (!ReadStructAt(file, nameOffset, hint))
                    continue;

                std::string name;
                if (!ReadCStringAt(file, nameOffset + sizeof(WORD), name))
                    continue;

                result.totalImports++;
                result.allImportedFunctions.push_back(name);
                if (suspiciousSet.count(ToLowerCopy(name)) > 0)
                    result.suspiciousImports.push_back(name);
            }
        }
    }

    result.importTableParsed = true;
    result.suspiciousImportCount = static_cast<unsigned int>(result.suspiciousImports.size());

    if (result.suspiciousImportCount == 0)
        AddNoteUnique(result.notes, "No suspicious imported APIs detected");
    else
        AddNoteUnique(result.notes, "Suspicious imported APIs were detected");

    if (HasImport(result.allImportedFunctions, "OpenProcess") &&
        HasImport(result.allImportedFunctions, "WriteProcessMemory") &&
        (HasImport(result.allImportedFunctions, "CreateRemoteThread") || HasImport(result.allImportedFunctions, "NtCreateThreadEx")))
    {
        AddNoteUnique(result.notes, "Potential process injection import pattern detected");
    }

    if ((HasImport(result.allImportedFunctions, "URLDownloadToFileA") || HasImport(result.allImportedFunctions, "URLDownloadToFileW") ||
         HasImport(result.allImportedFunctions, "InternetOpenUrlA") || HasImport(result.allImportedFunctions, "InternetOpenUrlW")) &&
        (HasImport(result.allImportedFunctions, "WinExec") || HasImport(result.allImportedFunctions, "ShellExecuteA") || HasImport(result.allImportedFunctions, "ShellExecuteW")))
    {
        AddNoteUnique(result.notes, "Download-and-execute import pattern detected");
    }

    if (HasImport(result.allImportedFunctions, "LoadLibraryA") && HasImport(result.allImportedFunctions, "GetProcAddress"))
        AddNoteUnique(result.notes, "Dynamic API resolution pattern detected");

    if (HasImport(result.allImportedFunctions, "IsDebuggerPresent") || HasImport(result.allImportedFunctions, "CheckRemoteDebuggerPresent"))
        AddNoteUnique(result.notes, "Anti-analysis import pattern detected");

    if ((HasImport(result.allImportedFunctions, "WSAStartup") || HasImport(result.allImportedFunctions, "socket") || HasImport(result.allImportedFunctions, "connect")) &&
        result.suspiciousImportCount > 0)
    {
        AddNoteUnique(result.notes, "Network-capable behavior indicators detected");
    }

    const bool hasOpenProcess = HasImport(result.allImportedFunctions, "OpenProcess");
    const bool hasVirtualAllocEx = HasImport(result.allImportedFunctions, "VirtualAllocEx");
    const bool hasWriteProcessMemory = HasImport(result.allImportedFunctions, "WriteProcessMemory");
    const bool hasRemoteThread = HasImport(result.allImportedFunctions, "CreateRemoteThread") || HasImport(result.allImportedFunctions, "NtCreateThreadEx") || HasImport(result.allImportedFunctions, "QueueUserAPC");
    if (hasOpenProcess && (hasVirtualAllocEx || hasWriteProcessMemory) && hasRemoteThread)
        AddClusterUnique(result.capabilityClusters, "Process Injection");

    const bool hasLoadLibraryFamily = HasAnyImport(result.allImportedFunctions, {"LoadLibraryA", "LoadLibraryW", "LdrLoadDll"});
    const bool hasGetProcAddressFamily = HasAnyImport(result.allImportedFunctions, {"GetProcAddress", "LdrGetProcedureAddress"});
    if (hasLoadLibraryFamily && hasGetProcAddressFamily)
        AddClusterUnique(result.capabilityClusters, "Dynamic API Resolution");

    int antiDebugImportCount = 0;
    for (const auto& name : {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW", "NtQueryInformationProcess", "ZwQueryInformationProcess"})
    {
        if (HasImport(result.allImportedFunctions, name))
            ++antiDebugImportCount;
    }
    if (antiDebugImportCount >= 2)
        AddClusterUnique(result.capabilityClusters, "Anti-Debug / Anti-Analysis");

    const bool hasServicePersistence = HasAnyImport(result.allImportedFunctions, {"CreateServiceA", "CreateServiceW"}) && HasAnyImport(result.allImportedFunctions, {"StartServiceA", "StartServiceW"});
    const bool hasAutorunPersistence = HasAnyImport(result.allImportedFunctions, {"RegSetValueExA", "RegSetValueExW"}) && HasAnyImport(result.allImportedFunctions, {"CopyFileA", "CopyFileW", "MoveFileExA", "MoveFileExW"});
    if (hasServicePersistence || hasAutorunPersistence)
        AddClusterUnique(result.capabilityClusters, "Persistence");

    if (HasAnyImport(result.allImportedFunctions, {"InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen", "WinHttpConnect", "WSAStartup", "socket", "connect", "send", "recv"}))
        AddClusterUnique(result.capabilityClusters, "Network Beaconing / C2");

    int execImportCount = 0;
    for (const auto& name : {"ShellExecuteA", "ShellExecuteW", "WinExec", "CreateProcessA", "CreateProcessW"})
    {
        if (HasImport(result.allImportedFunctions, name))
            ++execImportCount;
    }
    if (execImportCount >= 2)
        AddClusterUnique(result.capabilityClusters, "Execution / LOLBin Launching");

    if (HasImport(result.allImportedFunctions, "CryptUnprotectData") ||
        (HasAnyImport(result.allImportedFunctions, {"FindFirstFileA", "FindFirstFileW"}) && HasAnyImport(result.allImportedFunctions, {"FindNextFileA", "FindNextFileW"})))
    {
        AddClusterUnique(result.capabilityClusters, "Discovery / Secret Access");
    }

    for (const auto& cluster : result.capabilityClusters)
        AddNoteUnique(result.notes, "Capability cluster detected: " + cluster);

    return result;
}
