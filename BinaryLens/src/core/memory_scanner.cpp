#include "core/memory_scanner.h"
#include "common/string_utils.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include "asm/asm_bridge.h"

#include <algorithm>
#include <cctype>
#include <string>

// memory suspicion heuristics aimed at injection, allocation, and raw execution behavior.

#pragma comment(lib, "Psapi.lib")

// memory oriented helper rules used to weight allocation and execution traces.
namespace
{
    // these helpers stay tiny because runtime memory context is only an enrichment pass.
    std::string ToLowerCopy(std::string value)
    // normalizes text here so later comparisons stay simple and predictable.
    {
        return bl::common::ToLowerCopy(std::move(value));
    }

    // process names come back as wide strings on windows, so convert them once at the edge.
    std::string WideToUtf8(const wchar_t* value)
    // keeps the wide to utf8 step local to this memory scan logic file so callers can stay focused on intent.
    {
        if (!value || !*value)
            return {};

        const int required = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        if (required <= 1)
            return {};

        std::string utf8(static_cast<std::size_t>(required), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value, -1, utf8.data(), required, nullptr, nullptr);
        utf8.pop_back();
        return utf8;
    }
}

// this only enriches static results when a matching process is already alive.
// this only enriches static results when a matching process is already alive.
MemoryScannerResult AnalyzeRuntimeMemoryContext(const FileInfo& info)
// runs the analyze runtime memory context pass and returns a focused result for the broader memory scan logic pipeline.
{
    MemoryScannerResult result;
    if (!info.isPELike || info.name.empty())
        return result;

    // matching by executable name is a compromise between usefulness and keeping this pass cheap.
    const std::string targetName = ToLowerCopy(info.name);
    // process name matching is a cheap pivot before any deeper memory query.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return result;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            const std::string exe = WideToUtf8(pe.szExeFile);
            if (ToLowerCopy(exe) != targetName)
                continue;

            ++result.matchingProcessCount;
            // process opening is best-effort because protected processes are common on real systems.
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!process)
            {
                // keep the finding explicit so the analyst knows a live process matched even when deeper inspection was blocked.
                result.findings.push_back("Matching running process found but memory query was limited by access rights");
                continue;
            }

            HMODULE modules[64] = {};
            DWORD needed = 0;
            if (EnumProcessModules(process, modules, sizeof(modules), &needed))
            {
                const unsigned int moduleCount = needed / sizeof(HMODULE);
                result.findings.push_back("Matching running process found with approximately " + std::to_string(moduleCount) + " loaded modules");

                // a tiny header read is enough for opcode flavoring without a full dump.
                unsigned char moduleHeader[128] = {};
                SIZE_T bytesRead = 0;
                if (moduleCount > 0 && ReadProcessMemory(process, modules[0], moduleHeader, sizeof(moduleHeader), &bytesRead) && bytesRead > 0)
                {
                    const bl::asmbridge::EntrypointAsmProfile moduleProfile =
                        bl::asmbridge::ProfileEntrypointStub(moduleHeader, static_cast<std::size_t>(bytesRead));
                    const std::string moduleDescription = bl::asmbridge::DescribeEntrypointProfile(moduleProfile);
                    if (!moduleDescription.empty())
                    {
                        result.findings.push_back("In-memory module header opcode profile: " + moduleDescription);
                    }

                    static const std::uint8_t syscallPattern[] = { 0x0F, 0x05 };
                    const bl::asmbridge::PatternScanResult syscallHits =
                        bl::asmbridge::FindPatternMasked(moduleHeader,
                                                         static_cast<std::size_t>(bytesRead),
                                                         syscallPattern,
                                                         "xx",
                                                         sizeof(syscallPattern));
                    if (syscallHits.found)
                    {
                        // syscall bytes are supporting telemetry only; the scanner is not trying to prove direct syscalls here.
                        result.findings.push_back("In-memory module header contains syscall-style opcode bytes near offset " + std::to_string(syscallHits.firstMatchOffset));
                    }
                }
            }
            else
            {
                result.findings.push_back("Matching running process found; module enumeration was not available");
            }

            // architecture context is surfaced because it helps explain mixed x86/x64 behavior later.
            BOOL wow64 = FALSE;
            if (IsWow64Process(process, &wow64))
            {
                result.findings.push_back(wow64
                    ? "Matching running process is a WOW64 process"
                    : "Matching running process is not running under WOW64");
            }

            CloseHandle(process);
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return result;
}
