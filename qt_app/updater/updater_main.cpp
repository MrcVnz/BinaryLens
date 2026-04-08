#include <windows.h>
#include <shellapi.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace
{
    std::wstring Quote(const std::wstring& value)
    // keeps the quote step local to this updater startup file so callers can stay focused on intent.
    {
        return L"\"" + value + L"\"";
    }

    void SleepMs(int milliseconds)
    // keeps the sleep ms step local to this updater startup file so callers can stay focused on intent.
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }

    bool WaitForFileUnlock(const fs::path& target, int retries = 240, int delayMs = 500)
    // keeps the wait for file unlock step local to this updater startup file so callers can stay focused on intent.
    {
        if (target.empty())
            return false;

        for (int i = 0; i < retries; ++i)
        {
            HANDLE handle = ::CreateFileW(
                target.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (handle != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle);
                return true;
            }

            SleepMs(delayMs);
        }

        return false;
    }

    bool RunProcessAndWait(const std::wstring& commandLine, const fs::path& workingDir)
    // keeps the run process and wait step local to this updater startup file so callers can stay focused on intent.
    {
        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);

        PROCESS_INFORMATION processInfo{};
        std::wstring mutableCommandLine = commandLine;
        const BOOL created = ::CreateProcessW(
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            workingDir.empty() ? nullptr : workingDir.c_str(),
            &startupInfo,
            &processInfo);

        if (!created)
            return false;

        ::WaitForSingleObject(processInfo.hProcess, INFINITE);
        DWORD exitCode = 1;
        ::GetExitCodeProcess(processInfo.hProcess, &exitCode);
        ::CloseHandle(processInfo.hThread);
        ::CloseHandle(processInfo.hProcess);
        return exitCode == 0;
    }

    bool StartDetached(const fs::path& executable, const std::wstring& parameters, const fs::path& workingDir)
    // keeps the start detached step local to this updater startup file so callers can stay focused on intent.
    {
        const HINSTANCE instance = ::ShellExecuteW(
            nullptr,
            L"open",
            executable.c_str(),
            parameters.empty() ? nullptr : parameters.c_str(),
            workingDir.empty() ? nullptr : workingDir.c_str(),
            SW_SHOWNORMAL);

        return reinterpret_cast<INT_PTR>(instance) > 32;
    }

    std::wstring ReadArgValue(const std::vector<std::wstring>& args, const std::wstring& name)
    // reads the read arg value input here so bounds and fallback behavior stay local to this module.
    {
        for (size_t i = 0; i + 1 < args.size(); ++i)
        {
            if (args[i] == name)
                return args[i + 1];
        }
        return L"";
    }

    fs::path FindExtractedRoot(const fs::path& extractRoot)
    // keeps the find extracted root step local to this updater startup file so callers can stay focused on intent.
    {
        const fs::path direct = extractRoot / L"BinaryLensQt.exe";
        if (fs::exists(direct))
            return extractRoot;

        for (const auto& entry : fs::directory_iterator(extractRoot))
        {
            if (!entry.is_directory())
                continue;

            const fs::path candidate = entry.path() / L"BinaryLensQt.exe";
            if (fs::exists(candidate))
                return entry.path();
        }

        return {};
    }

    bool ApplyPortableUpdate(const fs::path& packagePath, const fs::path& appDir, const fs::path& restartExe)
    // handles the apply portable update ui work here so widget state changes do not leak across the file.
    {
        if (!WaitForFileUnlock(restartExe))
            return false;

        const fs::path extractRoot = packagePath.parent_path() / L"portable_extract";
        std::error_code ec;
        fs::remove_all(extractRoot, ec);
        fs::create_directories(extractRoot, ec);
        if (ec)
            return false;

        const fs::path powershellExe = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        const std::wstring expandCommand =
            Quote(powershellExe.wstring()) +
            L" -NoProfile -ExecutionPolicy Bypass -Command " +
            Quote(L"Expand-Archive -LiteralPath " + Quote(packagePath.wstring()) + L" -DestinationPath " + Quote(extractRoot.wstring()) + L" -Force");
        if (!RunProcessAndWait(expandCommand, extractRoot))
            return false;

        const fs::path sourceRoot = FindExtractedRoot(extractRoot);
        if (sourceRoot.empty())
            return false;

        const fs::path robocopyExe = L"C:\\Windows\\System32\\robocopy.exe";
        const std::wstring robocopyCommand =
            Quote(robocopyExe.wstring()) + L" " +
            Quote(sourceRoot.wstring()) + L" " +
            Quote(appDir.wstring()) +
            L" /E /R:2 /W:1 /NFL /NDL /NJH /NJS /NP /XF BinaryLensUpdater.exe";

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};
        std::wstring mutableCommandLine = robocopyCommand;
        const BOOL created = ::CreateProcessW(
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            appDir.c_str(),
            &startupInfo,
            &processInfo);
        if (!created)
            return false;

        ::WaitForSingleObject(processInfo.hProcess, INFINITE);
        DWORD robocopyExit = 16;
        ::GetExitCodeProcess(processInfo.hProcess, &robocopyExit);
        ::CloseHandle(processInfo.hThread);
        ::CloseHandle(processInfo.hProcess);
        if (robocopyExit > 7)
            return false;

        SleepMs(750);
        return StartDetached(restartExe, L"", appDir);
    }

    bool ApplyInstallerUpdate(const fs::path& packagePath, const fs::path& appDir, const fs::path& restartExe)
    // handles the apply installer update ui work here so widget state changes do not leak across the file.
    {
        if (!WaitForFileUnlock(restartExe))
            return false;

        const std::wstring installerCommand =
            Quote(packagePath.wstring()) +
            L" /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /DIR=" + Quote(appDir.wstring());
        if (!RunProcessAndWait(installerCommand, appDir))
            return false;

        SleepMs(1200);
        return StartDetached(restartExe, L"", appDir);
    }
}

int wmain(int argc, wchar_t* argv[])
// keeps the wmain step local to this updater startup file so callers can stay focused on intent.
{
    std::vector<std::wstring> args;
    args.reserve(static_cast<size_t>(argc));
    for (int i = 1; i < argc; ++i)
        args.emplace_back(argv[i]);

    const std::wstring mode = ReadArgValue(args, L"--mode");
    const fs::path packagePath = ReadArgValue(args, L"--package");
    const fs::path appDir = ReadArgValue(args, L"--app-dir");
    const fs::path restartExe = ReadArgValue(args, L"--restart-exe");

    if (mode.empty() || packagePath.empty() || appDir.empty() || restartExe.empty())
        return 2;

    if (mode == L"portable")
        return ApplyPortableUpdate(packagePath, appDir, restartExe) ? 0 : 1;

    if (mode == L"installer")
        return ApplyInstallerUpdate(packagePath, appDir, restartExe) ? 0 : 1;

    return 3;
}
