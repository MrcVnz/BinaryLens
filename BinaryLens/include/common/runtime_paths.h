#pragma once

// trusted runtime paths used for config, rules, plugins, and analysis cache.
#include <windows.h>

#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
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

    inline std::string ToLowerAsciiCopy(std::string value)
    {
        for (char& ch : value)
        {
            if (ch >= 'A' && ch <= 'Z')
                ch = static_cast<char>(ch - 'A' + 'a');
        }
        return value;
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

    inline std::filesystem::path GetRuntimeConfigDirectoryPath()
    {
        return EnsureDirectoryPath(GetAppDataDirectoryPath());
    }

    inline std::filesystem::path GetAppDataConfigPath()
    {
        return GetRuntimeConfigDirectoryPath() / "config.json";
    }

    inline std::filesystem::path GetBundledConfigPath()
    {
        return GetModuleDirectoryPath() / "config" / "config.json";
    }

    inline std::filesystem::path GetBundledExampleConfigPath()
    {
        return GetModuleDirectoryPath() / "config" / "config.example.json";
    }

    inline std::filesystem::path NormalizeWeaklyCanonical(const std::filesystem::path& path)
    {
        std::error_code ec;
        const std::filesystem::path absolutePath = std::filesystem::absolute(path, ec);
        if (ec)
            return path.lexically_normal();

        const std::filesystem::path normalized = std::filesystem::weakly_canonical(absolutePath, ec);
        if (ec)
            return absolutePath.lexically_normal();
        return normalized;
    }

    inline bool PathStartsWith(const std::filesystem::path& childPath, const std::filesystem::path& rootPath)
    {
        std::string child = ToLowerAsciiCopy(WideToUtf8Copy(NormalizeWeaklyCanonical(childPath).wstring()));
        std::string root = ToLowerAsciiCopy(WideToUtf8Copy(NormalizeWeaklyCanonical(rootPath).wstring()));
        if (child.empty() || root.empty())
            return false;
        if (child == root)
            return true;
        if (root.back() != '/')
            root.push_back('/');
        return child.rfind(root, 0) == 0;
    }

    inline bool IsTrustedRuntimeFile(const std::filesystem::path& candidate,
                                     const std::filesystem::path& trustedRoot,
                                     std::uintmax_t maxSizeBytes)
    {
        std::error_code ec;
        const std::filesystem::file_status status = std::filesystem::symlink_status(candidate, ec);
        if (ec || !std::filesystem::exists(status) || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status))
            return false;

        if (!PathStartsWith(candidate, trustedRoot))
            return false;

        const std::uintmax_t fileSize = std::filesystem::file_size(candidate, ec);
        if (ec || fileSize == static_cast<std::uintmax_t>(-1) || fileSize > maxSizeBytes)
            return false;

        return true;
    }

    inline std::vector<std::filesystem::path> GetTrustedRuleDirectories()
    {
        const std::filesystem::path moduleDir = GetModuleDirectoryPath();
        return {
            moduleDir / "rules",
            moduleDir / "BinaryLens" / "rules"
        };
    }

    inline std::vector<std::filesystem::path> GetTrustedPluginDirectories()
    {
        const std::filesystem::path moduleDir = GetModuleDirectoryPath();
        return {
            moduleDir / "plugins",
            moduleDir / "BinaryLens" / "plugins"
        };
    }

    inline std::filesystem::path GetAnalysisCacheDirectory()
    {
        return EnsureDirectoryPath(GetAppDataDirectoryPath() / "cache");
    }
}
