#pragma once

// trusted runtime paths used for config, rules, plugins, and analysis cache.
#include <windows.h>

#include <filesystem>
#include <string>
#include <vector>

namespace bl::common
{
    inline std::wstring Utf8ToWideCopy(const std::string& input)
    {
        if (input.empty())
            return std::wstring();

        const int size = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (size <= 0)
            return std::wstring();

        std::wstring output(static_cast<std::size_t>(size), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, output.data(), size);
        output.pop_back();
        return output;
    }

    inline std::string WideToUtf8Copy(const std::wstring& input)
    {
        if (input.empty())
            return std::string();

        const int size = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0)
            return std::string();

        std::string output(static_cast<std::size_t>(size), '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, output.data(), size, nullptr, nullptr);
        output.pop_back();
        return output;
    }

    inline std::filesystem::path GetModuleDirectoryPath()
    {
        char exePath[MAX_PATH] = {};
        if (GetModuleFileNameA(nullptr, exePath, MAX_PATH) == 0)
            return std::filesystem::current_path();

        std::filesystem::path modulePath(exePath);
        return modulePath.has_parent_path() ? modulePath.parent_path() : std::filesystem::current_path();
    }

    inline std::filesystem::path GetAppDataDirectoryPath()
    {
        char appDataPath[MAX_PATH] = {};
        if (GetEnvironmentVariableA("APPDATA", appDataPath, MAX_PATH) == 0)
            return std::filesystem::current_path() / "BinaryLens";
        return std::filesystem::path(appDataPath) / "BinaryLens";
    }

    inline std::filesystem::path EnsureDirectoryPath(const std::filesystem::path& path)
    {
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
        return path;
    }

    inline std::vector<std::filesystem::path> GetTrustedRuleDirectories()
    {
        const std::filesystem::path moduleDir = GetModuleDirectoryPath();
        return {
            moduleDir / "rules",
            moduleDir / "BinaryLens" / "rules",
            std::filesystem::current_path() / "rules",
            std::filesystem::current_path() / "BinaryLens" / "rules",
            GetAppDataDirectoryPath() / "rules"
        };
    }

    inline std::vector<std::filesystem::path> GetTrustedPluginDirectories()
    {
        const std::filesystem::path moduleDir = GetModuleDirectoryPath();
        return {
            moduleDir / "plugins",
            moduleDir / "BinaryLens" / "plugins",
            std::filesystem::current_path() / "plugins",
            std::filesystem::current_path() / "BinaryLens" / "plugins",
            GetAppDataDirectoryPath() / "plugins"
        };
    }

    inline std::filesystem::path GetAnalysisCacheDirectory()
    {
        return EnsureDirectoryPath(GetAppDataDirectoryPath() / "cache");
    }
}
