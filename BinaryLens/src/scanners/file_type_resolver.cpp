#include "scanners/file_type_resolver.h"
#include "common/string_utils.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace
{
    using bl::common::ToLowerCopy;
    using bl::common::TrimCopy;

    bool StartsWithBytes(const std::vector<unsigned char>& data, std::initializer_list<unsigned char> bytes)
    // keeps byte-signature checks readable without scattering raw loops through the detector.
    {
        if (data.size() < bytes.size())
            return false;

        std::size_t index = 0;
        for (const unsigned char value : bytes)
        {
            if (data[index] != value)
                return false;
            ++index;
        }
        return true;
    }

    bool MatchesBytesAt(const std::vector<unsigned char>& data,
                        std::size_t offset,
                        std::initializer_list<unsigned char> bytes)
    // offset-aware matching is used for container formats whose markers do not start at byte zero.
    {
        if (offset > data.size() || data.size() - offset < bytes.size())
            return false;

        std::size_t index = 0;
        for (const unsigned char value : bytes)
        {
            if (data[offset + index] != value)
                return false;
            ++index;
        }
        return true;
    }

    std::uint32_t ReadLe32(const std::vector<unsigned char>& data, std::size_t offset)
    // reads small header fields locally so the rest of the file-type logic can stay intention-focused.
    {
        if (offset + 4 > data.size())
            return 0;

        return static_cast<std::uint32_t>(data[offset]) |
               (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
               (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
               (static_cast<std::uint32_t>(data[offset + 3]) << 24);
    }

    bool ContainsBinaryNulls(const std::vector<unsigned char>& data, std::size_t limit)
    // a quick null-byte pass helps avoid treating binary containers as plain text.
    {
        const std::size_t bounded = (std::min)(limit, data.size());
        for (std::size_t i = 0; i < bounded; ++i)
        {
            if (data[i] == 0)
                return true;
        }
        return false;
    }

    bool LooksPortableExecutable(const std::vector<unsigned char>& data)
    // mz alone is too permissive, so require the nt header marker when the header window is large enough.
    {
        if (data.size() < 0x40 || data[0] != 'M' || data[1] != 'Z')
            return false;

        const std::uint32_t peOffset = ReadLe32(data, 0x3Cu);
        if (peOffset == 0 || peOffset > data.size() || data.size() - peOffset < 4)
            return false;

        return MatchesBytesAt(data, peOffset, { 'P', 'E', 0x00, 0x00 });
    }

    std::string BuildAsciiSearchView(const std::vector<unsigned char>& data, std::size_t limit)
    // zip entry names and textual headers are easiest to probe once folded into one tolerant ascii view.
    {
        const std::size_t bounded = (std::min)(limit, data.size());
        std::string out;
        out.reserve(bounded);

        for (std::size_t i = 0; i < bounded; ++i)
        {
            const unsigned char c = data[i];
            if (c >= 32 && c <= 126)
                out.push_back(static_cast<char>(std::tolower(c)));
            else if (c == '\r' || c == '\n' || c == '\t')
                out.push_back(' ');
            else
                out.push_back(' ');
        }
        return out;
    }

    bool LooksLikeUtf16LeText(const std::vector<unsigned char>& data)
    // some windows text files arrive without a bom, so a light utf-16 pattern check keeps them classifiable.
    {
        const std::size_t bounded = (std::min)(data.size(), static_cast<std::size_t>(128));
        if (bounded < 8 || (bounded % 2) != 0)
            return false;

        std::size_t asciiPairs = 0;
        std::size_t zeroOddBytes = 0;
        for (std::size_t i = 0; i + 1 < bounded; i += 2)
        {
            const unsigned char lo = data[i];
            const unsigned char hi = data[i + 1];
            if ((lo >= 9 && lo <= 13) || (lo >= 32 && lo <= 126))
                ++asciiPairs;
            if (hi == 0)
                ++zeroOddBytes;
        }

        return asciiPairs >= 4 && zeroOddBytes * 2 >= (bounded / 2);
    }

    std::string DecodeUtf16LePreview(const std::vector<unsigned char>& data, std::size_t limit)
    // the detector only needs an ascii-oriented preview, not a full unicode conversion pipeline.
    {
        const std::size_t bounded = (std::min)(limit, data.size());
        std::string out;
        out.reserve(bounded / 2);

        for (std::size_t i = 0; i + 1 < bounded; i += 2)
        {
            const unsigned char lo = data[i];
            const unsigned char hi = data[i + 1];
            if (hi != 0)
                break;

            if ((lo >= 32 && lo <= 126) || lo == '\n' || lo == '\r' || lo == '\t')
                out.push_back(static_cast<char>(std::tolower(lo)));
            else if (!out.empty() && out.back() != ' ')
                out.push_back(' ');
        }
        return out;
    }

    std::string BuildTextPreview(const std::vector<unsigned char>& header, const std::string& printablePreview)
    // the caller may already have a printable cache from the streamed pass, so prefer that before re-sampling bytes.
    {
        if (!printablePreview.empty())
        {
            std::string folded = printablePreview.substr(0, (std::min)(printablePreview.size(), static_cast<std::size_t>(8192)));
            std::transform(folded.begin(), folded.end(), folded.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return folded;
        }

        if (header.size() >= 2 && header[0] == 0xFF && header[1] == 0xFE)
            return DecodeUtf16LePreview(std::vector<unsigned char>(header.begin() + 2, header.end()), 2048);

        if (LooksLikeUtf16LeText(header))
            return DecodeUtf16LePreview(header, 2048);

        return BuildAsciiSearchView(header, 4096);
    }

    bool LooksLikeTextContent(const std::vector<unsigned char>& header, const std::string& preview)
    // text classification stays conservative: visible structure must be present and binary nulls should stay rare.
    {
        const std::string trimmed = TrimCopy(preview);
        if (trimmed.size() < 2)
            return false;

        if (!ContainsBinaryNulls(header, 512))
            return true;

        if (header.size() >= 2 && header[0] == 0xFF && header[1] == 0xFE)
            return true;

        return LooksLikeUtf16LeText(header);
    }

    bool StartsWithToken(const std::string& text, const std::string& token)
    // a tiny wrapper keeps the text probes readable and consistent.
    {
        return text.size() >= token.size() && text.compare(0, token.size(), token) == 0;
    }

    bool ContainsToken(const std::string& text, const std::string& token)
    // content tests stay local because many type hints are expressed as simple token probes.
    {
        return text.find(token) != std::string::npos;
    }

    bool LooksLikeJsonText(const std::string& text)
    // json detection only fires on clear structural markers to keep arbitrary brace-heavy text from misclassifying.
    {
        const std::string trimmed = TrimCopy(text);
        if (trimmed.size() < 2)
            return false;

        if ((trimmed.front() == '{' && ContainsToken(trimmed, "\":")) ||
            (trimmed.front() == '[' && (ContainsToken(trimmed, "{") || ContainsToken(trimmed, "\"") || ContainsToken(trimmed, "]"))))
            return true;
        return false;
    }

    bool LooksLikeXmlText(const std::string& text)
    // xml and html stay separated because the ui wording is more useful when they are distinguished.
    {
        const std::string trimmed = TrimCopy(text);
        return StartsWithToken(trimmed, "<?xml") ||
               StartsWithToken(trimmed, "<configuration") ||
               StartsWithToken(trimmed, "<assembly") ||
               StartsWithToken(trimmed, "<manifest") ||
               StartsWithToken(trimmed, "<project") ||
               StartsWithToken(trimmed, "<svg");
    }

    bool LooksLikeHtmlText(const std::string& text)
    {
        const std::string trimmed = TrimCopy(text);
        return StartsWithToken(trimmed, "<!doctype html") ||
               StartsWithToken(trimmed, "<html") ||
               StartsWithToken(trimmed, "<head") ||
               StartsWithToken(trimmed, "<body") ||
               ContainsToken(trimmed, "<script") ||
               ContainsToken(trimmed, "<meta ");
    }

    bool LooksLikeCsvText(const std::string& text)
    // csv is treated as structured text only when repeated delimiters suggest columnar rows.
    {
        const std::string trimmed = TrimCopy(text);
        if (trimmed.empty())
            return false;

        const std::size_t firstBreak = trimmed.find('\n');
        if (firstBreak == std::string::npos)
            return false;

        const std::string line1 = trimmed.substr(0, firstBreak);
        const std::size_t secondBreak = trimmed.find('\n', firstBreak + 1);
        const std::string line2 = secondBreak == std::string::npos
            ? trimmed.substr(firstBreak + 1)
            : trimmed.substr(firstBreak + 1, secondBreak - firstBreak - 1);

        const std::size_t commas1 = std::count(line1.begin(), line1.end(), ',');
        const std::size_t commas2 = std::count(line2.begin(), line2.end(), ',');
        return commas1 >= 1 && commas1 == commas2;
    }

    std::string SpecificTypeFromText(const std::string& extension, const std::string& preview, std::string& family)
    // text formats are resolved after binary signatures so the app can still surface useful names for scripts and configs.
    {
        const std::string trimmed = TrimCopy(preview);
        const std::string ext = ToLowerCopy(extension);
        family.clear();

        if (ext == ".ps1" || ext == ".psm1" || StartsWithToken(trimmed, "#!") && (ContainsToken(trimmed, "pwsh") || ContainsToken(trimmed, "powershell")))
        {
            family = "script";
            return "PowerShell script";
        }
        if (ext == ".bat" || ext == ".cmd")
        {
            family = "script";
            return "Batch script";
        }
        if (ext == ".js" || ext == ".jse" || ext == ".mjs" || ext == ".cjs" || (StartsWithToken(trimmed, "#!") && ContainsToken(trimmed, "node")))
        {
            family = "script";
            return "JavaScript file";
        }
        if (ext == ".vbs" || ext == ".vbe")
        {
            family = "script";
            return "VBScript file";
        }
        if (ext == ".wsf" || ext == ".wsh" || ContainsToken(trimmed, "<job") || ContainsToken(trimmed, "<script language=\"vbscript\"") || ContainsToken(trimmed, "<script language=\"jscript\""))
        {
            family = "script";
            return "Windows Script File";
        }
        if (ext == ".hta" || ContainsToken(trimmed, "<hta:application"))
        {
            family = "script";
            return "HTA application";
        }
        if (ext == ".py" || (StartsWithToken(trimmed, "#!") && ContainsToken(trimmed, "python")))
        {
            family = "script";
            return "Python script";
        }
        if (ext == ".cpp" || ext == ".cc" || ext == ".cxx")
        {
            family = "text";
            return "C++ source file";
        }
        if (ext == ".hpp" || ext == ".hh" || ext == ".hxx")
        {
            family = "text";
            return "C++ header file";
        }
        if (ext == ".c")
        {
            family = "text";
            return "C source file";
        }
        if (ext == ".h")
        {
            family = "text";
            return "Header file";
        }
        if (ext == ".cs")
        {
            family = "text";
            return "C# source file";
        }
        if (ext == ".java")
        {
            family = "text";
            return "Java source file";
        }
        if (ext == ".go")
        {
            family = "text";
            return "Go source file";
        }
        if (ext == ".rs")
        {
            family = "text";
            return "Rust source file";
        }
        if (ext == ".php")
        {
            family = "script";
            return "PHP script";
        }
        if (ext == ".psd1")
        {
            family = "text";
            return "PowerShell data file";
        }
        if (ext == ".sql")
        {
            family = "text";
            return "SQL script";
        }
        if (ext == ".reg" || ContainsToken(trimmed, "windows registry editor version"))
        {
            family = "text";
            return "Registry export";
        }
        if (ext == ".svg" || (LooksLikeXmlText(trimmed) && ContainsToken(trimmed, "<svg")))
        {
            family = "image";
            return "SVG image";
        }
        if (LooksLikeHtmlText(trimmed) || ext == ".html" || ext == ".htm" || ext == ".xhtml")
        {
            family = "document";
            return "HTML document";
        }
        if (LooksLikeXmlText(trimmed) || ext == ".xml" || ext == ".xaml" || ext == ".config" || ext == ".manifest" || ext == ".vcxproj" || ext == ".csproj" || ext == ".props" || ext == ".targets")
        {
            family = "document";
            return "XML document";
        }
        if (LooksLikeJsonText(trimmed) || ext == ".json")
        {
            family = "text";
            return "JSON document";
        }
        if (ext == ".yaml" || ext == ".yml")
        {
            family = "text";
            return "YAML document";
        }
        if (ext == ".toml")
        {
            family = "text";
            return "TOML document";
        }
        if (ext == ".csv" || LooksLikeCsvText(trimmed))
        {
            family = "text";
            return "CSV text";
        }
        if (ext == ".tsv")
        {
            family = "text";
            return "TSV text";
        }
        if (ext == ".ini" || ext == ".cfg" || ext == ".conf" || ext == ".properties")
        {
            family = "text";
            return "Configuration file";
        }
        if (ext == ".log")
        {
            family = "text";
            return "Log file";
        }
        if (ext == ".md")
        {
            family = "text";
            return "Markdown document";
        }
        if (ext == ".txt")
        {
            family = "text";
            return "Text document";
        }

        if (!trimmed.empty())
        {
            family = "text";
            return "Plain text";
        }
        return "";
    }

    std::string DisplayTypeFromExtension(const std::string& extension)
    // extension fallback keeps the ui informative even when a file provides no reliable signature.
    {
        const std::string ext = ToLowerCopy(extension);
        if (ext == ".exe") return "Windows executable";
        if (ext == ".dll") return "Windows DLL";
        if (ext == ".sys") return "Windows driver";
        if (ext == ".ocx") return "ActiveX control";
        if (ext == ".scr") return "Screensaver executable";
        if (ext == ".cpl") return "Control Panel item";
        if (ext == ".lnk") return "Windows shortcut";
        if (ext == ".msi") return "Windows installer package";
        if (ext == ".zip") return "ZIP archive";
        if (ext == ".rar") return "RAR archive";
        if (ext == ".7z") return "7z archive";
        if (ext == ".tar") return "TAR archive";
        if (ext == ".gz") return "GZIP archive";
        if (ext == ".bz2") return "BZIP2 archive";
        if (ext == ".xz") return "XZ archive";
        if (ext == ".cab") return "CAB archive";
        if (ext == ".iso" || ext == ".img") return "Disk image";
        if (ext == ".jar") return "Java archive";
        if (ext == ".apk") return "Android package";
        if (ext == ".doc") return "Word 97-2003 document";
        if (ext == ".xls") return "Excel 97-2003 spreadsheet";
        if (ext == ".ppt") return "PowerPoint 97-2003 presentation";
        if (ext == ".docx") return "Word document";
        if (ext == ".xlsx") return "Excel spreadsheet";
        if (ext == ".pptx") return "PowerPoint presentation";
        if (ext == ".docm") return "Word macro-enabled document";
        if (ext == ".xlsm") return "Excel macro-enabled spreadsheet";
        if (ext == ".pptm") return "PowerPoint macro-enabled presentation";
        if (ext == ".odt") return "OpenDocument text";
        if (ext == ".ods") return "OpenDocument spreadsheet";
        if (ext == ".odp") return "OpenDocument presentation";
        if (ext == ".epub") return "EPUB ebook";
        if (ext == ".pdf") return "PDF document";
        if (ext == ".rtf") return "RTF document";
        if (ext == ".png") return "PNG image";
        if (ext == ".jpg" || ext == ".jpeg") return "JPEG image";
        if (ext == ".gif") return "GIF image";
        if (ext == ".bmp") return "Bitmap image";
        if (ext == ".tif" || ext == ".tiff") return "TIFF image";
        if (ext == ".ico") return "Icon file";
        if (ext == ".webp") return "WEBP image";
        if (ext == ".wav") return "WAV audio";
        if (ext == ".mp3") return "MP3 audio";
        if (ext == ".m4a") return "M4A audio";
        if (ext == ".flac") return "FLAC audio";
        if (ext == ".ogg") return "Ogg media";
        if (ext == ".wma") return "WMA audio";
        if (ext == ".mid" || ext == ".midi") return "MIDI audio";
        if (ext == ".mp4") return "MP4 video";
        if (ext == ".mov") return "QuickTime video";
        if (ext == ".avi") return "AVI video";
        if (ext == ".wmv") return "WMV video";
        if (ext == ".ogv") return "Ogg video";
        if (ext == ".ttf" || ext == ".otf" || ext == ".woff" || ext == ".woff2") return "Font file";
        if (ext == ".sqlite" || ext == ".db") return "SQLite database";
        if (ext == ".chm") return "Compiled HTML Help";
        if (ext == ".ps1" || ext == ".psm1") return "PowerShell script";
        if (ext == ".cpp" || ext == ".cc" || ext == ".cxx") return "C++ source file";
        if (ext == ".hpp" || ext == ".hh" || ext == ".hxx") return "C++ header file";
        if (ext == ".c") return "C source file";
        if (ext == ".h") return "Header file";
        if (ext == ".cs") return "C# source file";
        if (ext == ".java") return "Java source file";
        if (ext == ".go") return "Go source file";
        if (ext == ".rs") return "Rust source file";
        if (ext == ".php") return "PHP script";
        if (ext == ".bat" || ext == ".cmd") return "Batch script";
        if (ext == ".js" || ext == ".jse" || ext == ".mjs" || ext == ".cjs") return "JavaScript file";
        if (ext == ".vbs" || ext == ".vbe") return "VBScript file";
        if (ext == ".wsf" || ext == ".wsh") return "Windows Script File";
        if (ext == ".hta") return "HTA application";
        if (ext == ".json") return "JSON document";
        if (ext == ".xml") return "XML document";
        if (ext == ".html" || ext == ".htm") return "HTML document";
        if (ext == ".csv") return "CSV text";
        if (ext == ".yaml" || ext == ".yml") return "YAML document";
        if (ext == ".toml") return "TOML document";
        if (ext == ".ini" || ext == ".cfg" || ext == ".conf") return "Configuration file";
        if (ext == ".txt" || ext == ".log" || ext == ".md") return "Text document";
        return "Generic file";
    }

    std::string ExpectedFamilyFromExtension(const std::string& extension)
    // mismatch checks stay conservative by comparing broad families instead of every individual label.
    {
        const std::string ext = ToLowerCopy(extension);

        static const std::set<std::string> peExts = { ".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".com" };
        static const std::set<std::string> installerExts = { ".msi" };
        static const std::set<std::string> shortcutExts = { ".lnk" };
        static const std::set<std::string> scriptExts = { ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".js", ".jse", ".mjs", ".cjs", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".py" };
        static const std::set<std::string> archiveExts = { ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".jar", ".apk", ".iso", ".img" };
        static const std::set<std::string> documentExts = { ".pdf", ".rtf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".odt", ".ods", ".odp", ".epub", ".html", ".htm", ".xml" };
        static const std::set<std::string> imageExts = { ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".ico", ".webp", ".svg" };
        static const std::set<std::string> audioExts = { ".wav", ".mp3", ".m4a", ".flac", ".ogg", ".wma", ".mid", ".midi" };
        static const std::set<std::string> videoExts = { ".mp4", ".mov", ".avi", ".wmv", ".ogv" };
        static const std::set<std::string> textExts = { ".txt", ".log", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".csv", ".tsv", ".reg", ".sql", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".c", ".h", ".cs", ".java", ".go", ".rs" };

        if (peExts.count(ext) > 0)
            return "pe";
        if (installerExts.count(ext) > 0)
            return "installer";
        if (shortcutExts.count(ext) > 0)
            return "shortcut";
        if (scriptExts.count(ext) > 0)
            return "script";
        if (archiveExts.count(ext) > 0)
            return "archive";
        if (documentExts.count(ext) > 0)
            return "document";
        if (imageExts.count(ext) > 0)
            return "image";
        if (audioExts.count(ext) > 0)
            return "audio";
        if (videoExts.count(ext) > 0)
            return "video";
        if (textExts.count(ext) > 0)
            return "text";
        return "";
    }

    bool IsActiveContentFamily(const std::string& family)
    {
        return family == "pe" || family == "installer" || family == "script" || family == "shortcut" ||
               family == "elf" || family == "macho" || family == "java" || family == "wasm";
    }

    bool IsPassiveContentFamily(const std::string& family)
    {
        return family == "archive" || family == "document" || family == "image" || family == "audio" ||
               family == "video" || family == "text" || family == "font" || family == "database" || family == "disk";
    }

    void ApplyStrongType(bl::filetype::FileTypeDetection& out,
                         const std::string& displayedType,
                         const std::string& realType,
                         const std::string& family)
    // one helper keeps the concrete match branches compact and avoids drift between display and real labels.
    {
        out.displayedType = displayedType;
        out.realType = realType;
        out.familyTag = family;
    }
}

namespace bl::filetype
{
    FileTypeDetection DetectFileType(const std::string& fileName,
                                     const std::string& extension,
                                     const std::vector<unsigned char>& header,
                                     const std::string& printablePreview)
    {
        FileTypeDetection out;
        const std::string ext = !extension.empty() ? ToLowerCopy(extension) : ToLowerCopy([&]() {
            const std::size_t dot = fileName.find_last_of('.');
            return dot == std::string::npos ? std::string() : fileName.substr(dot);
        }());
        const std::string asciiHeader = BuildAsciiSearchView(header, 65536);
        const std::string textPreview = BuildTextPreview(header, printablePreview);
        const bool textLike = LooksLikeTextContent(header, textPreview);

        out.displayedType = DisplayTypeFromExtension(ext);
        out.realType = "Unknown / generic";
        out.familyTag = "unknown";
        out.scriptLike = ExpectedFamilyFromExtension(ext) == "script";

        if (LooksPortableExecutable(header))
        {
            out.peLike = true;
            if (ext == ".dll")
                ApplyStrongType(out, "Windows DLL", "Portable Executable (DLL)", "pe");
            else if (ext == ".sys")
                ApplyStrongType(out, "Windows driver", "Portable Executable (driver)", "pe");
            else if (ext == ".ocx")
                ApplyStrongType(out, "ActiveX control", "Portable Executable (ActiveX control)", "pe");
            else if (ext == ".scr")
                ApplyStrongType(out, "Screensaver executable", "Portable Executable (screensaver)", "pe");
            else if (ext == ".cpl")
                ApplyStrongType(out, "Control Panel item", "Portable Executable (Control Panel item)", "pe");
            else
                ApplyStrongType(out, ext == ".exe" ? "Windows executable" : "Portable Executable (PE)", "Portable Executable (PE)", "pe");
        }
        else if (StartsWithBytes(header, { 0x7F, 'E', 'L', 'F' }))
        {
            ApplyStrongType(out, "ELF executable/object", "ELF binary", "elf");
        }
        else if (StartsWithBytes(header, { 0xCA, 0xFE, 0xBA, 0xBE }) && ext == ".class")
        {
            ApplyStrongType(out, "Java class file", "Java class file", "java");
        }
        else if (StartsWithBytes(header, { 0xFE, 0xED, 0xFA, 0xCE }) ||
                 StartsWithBytes(header, { 0xFE, 0xED, 0xFA, 0xCF }) ||
                 StartsWithBytes(header, { 0xCE, 0xFA, 0xED, 0xFE }) ||
                 StartsWithBytes(header, { 0xCF, 0xFA, 0xED, 0xFE }) ||
                 StartsWithBytes(header, { 0xCA, 0xFE, 0xBA, 0xBE }))
        {
            ApplyStrongType(out, "Mach-O binary", "Mach-O binary", "macho");
        }
        else if (StartsWithBytes(header, { 0x00, 0x61, 0x73, 0x6D }))
        {
            ApplyStrongType(out, "WebAssembly module", "WebAssembly module", "wasm");
        }
        else if (StartsWithBytes(header, { 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00 }))
        {
            ApplyStrongType(out, "Windows shortcut", "Windows shortcut", "shortcut");
        }
        else if (StartsWithBytes(header, { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }))
        {
            if (ext == ".msi")
                ApplyStrongType(out, "Windows installer package", "Windows Installer database", "installer");
            else if (ext == ".doc")
                ApplyStrongType(out, "Word 97-2003 document", "OLE compound document", "document");
            else if (ext == ".xls")
                ApplyStrongType(out, "Excel 97-2003 spreadsheet", "OLE compound document", "document");
            else if (ext == ".ppt")
                ApplyStrongType(out, "PowerPoint 97-2003 presentation", "OLE compound document", "document");
            else if (ext == ".msg")
                ApplyStrongType(out, "Outlook message", "OLE compound document", "document");
            else
                ApplyStrongType(out, out.displayedType != "Generic file" ? out.displayedType : "OLE compound document", "OLE compound document", ext == ".msi" ? "installer" : "document");
        }
        else if (StartsWithBytes(header, { 'P', 'K', 0x03, 0x04 }) ||
                 StartsWithBytes(header, { 'P', 'K', 0x05, 0x06 }) ||
                 StartsWithBytes(header, { 'P', 'K', 0x07, 0x08 }))
        {
            const bool hasWordTree = ContainsToken(asciiHeader, "word/");
            const bool hasExcelTree = ContainsToken(asciiHeader, "xl/");
            const bool hasPowerPointTree = ContainsToken(asciiHeader, "ppt/");
            const bool hasManifest = ContainsToken(asciiHeader, "meta-inf/manifest.mf");
            const bool hasAndroidManifest = ContainsToken(asciiHeader, "androidmanifest.xml");
            const bool hasEpubMarker = ContainsToken(asciiHeader, "mimetypeapplication/epub+zip");
            const bool hasOdtMarker = ContainsToken(asciiHeader, "mimetypeapplication/vnd.oasis.opendocument.text");
            const bool hasOdsMarker = ContainsToken(asciiHeader, "mimetypeapplication/vnd.oasis.opendocument.spreadsheet");
            const bool hasOdpMarker = ContainsToken(asciiHeader, "mimetypeapplication/vnd.oasis.opendocument.presentation");

            if (hasWordTree || ext == ".docx" || ext == ".docm" || ext == ".dotx" || ext == ".dotm")
            {
                ApplyStrongType(out,
                                ext == ".docm" || ext == ".dotm" ? "Word macro-enabled document" : "Word document",
                                "OOXML Word document",
                                "document");
            }
            else if (hasExcelTree || ext == ".xlsx" || ext == ".xlsm" || ext == ".xltx" || ext == ".xltm")
            {
                ApplyStrongType(out,
                                ext == ".xlsm" || ext == ".xltm" ? "Excel macro-enabled spreadsheet" : "Excel spreadsheet",
                                "OOXML Excel workbook",
                                "document");
            }
            else if (hasPowerPointTree || ext == ".pptx" || ext == ".pptm" || ext == ".potx" || ext == ".potm")
            {
                ApplyStrongType(out,
                                ext == ".pptm" || ext == ".potm" ? "PowerPoint macro-enabled presentation" : "PowerPoint presentation",
                                "OOXML PowerPoint presentation",
                                "document");
            }
            else if (hasAndroidManifest || ext == ".apk")
            {
                ApplyStrongType(out, "Android package", "ZIP-based Android package", "archive");
                out.archiveInspectionCandidate = true;
            }
            else if (hasManifest || ext == ".jar" || ext == ".war" || ext == ".ear")
            {
                ApplyStrongType(out, "Java archive", "ZIP-based Java archive", "archive");
                out.archiveInspectionCandidate = true;
            }
            else if (hasEpubMarker || ext == ".epub")
            {
                ApplyStrongType(out, "EPUB ebook", "ZIP-based EPUB document", "document");
            }
            else if (hasOdtMarker || ext == ".odt")
            {
                ApplyStrongType(out, "OpenDocument text", "ZIP-based OpenDocument text", "document");
            }
            else if (hasOdsMarker || ext == ".ods")
            {
                ApplyStrongType(out, "OpenDocument spreadsheet", "ZIP-based OpenDocument spreadsheet", "document");
            }
            else if (hasOdpMarker || ext == ".odp")
            {
                ApplyStrongType(out, "OpenDocument presentation", "ZIP-based OpenDocument presentation", "document");
            }
            else
            {
                ApplyStrongType(out, out.displayedType != "Generic file" ? out.displayedType : "ZIP archive", "ZIP archive", "archive");
                out.archiveInspectionCandidate = ext != ".docx" && ext != ".xlsx" && ext != ".pptx" &&
                                                ext != ".docm" && ext != ".xlsm" && ext != ".pptm" &&
                                                ext != ".odt" && ext != ".ods" && ext != ".odp" &&
                                                ext != ".epub";
            }
        }
        else if (StartsWithBytes(header, { 'R', 'a', 'r', '!', 0x1A, 0x07, 0x00 }) ||
                 StartsWithBytes(header, { 'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00 }))
        {
            ApplyStrongType(out, "RAR archive", "RAR archive", "archive");
            out.archiveInspectionCandidate = true;
        }
        else if (StartsWithBytes(header, { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }))
        {
            ApplyStrongType(out, "7z archive", "7z archive", "archive");
            out.archiveInspectionCandidate = true;
        }
        else if (StartsWithBytes(header, { 0x1F, 0x8B }))
        {
            ApplyStrongType(out, "GZIP archive", "GZIP archive", "archive");
        }
        else if (StartsWithBytes(header, { 'B', 'Z', 'h' }))
        {
            ApplyStrongType(out, "BZIP2 archive", "BZIP2 archive", "archive");
        }
        else if (StartsWithBytes(header, { 0xFD, '7', 'z', 'X', 'Z', 0x00 }))
        {
            ApplyStrongType(out, "XZ archive", "XZ archive", "archive");
        }
        else if (StartsWithBytes(header, { 'M', 'S', 'C', 'F' }))
        {
            ApplyStrongType(out, "CAB archive", "CAB archive", "archive");
            out.archiveInspectionCandidate = true;
        }
        else if (MatchesBytesAt(header, 257, { 'u', 's', 't', 'a', 'r' }))
        {
            ApplyStrongType(out, "TAR archive", "TAR archive", "archive");
        }
        else if (header.size() > 0x8005 && MatchesBytesAt(header, 0x8001, { 'C', 'D', '0', '0', '1' }))
        {
            ApplyStrongType(out, "Disk image", "ISO / optical disk image", "disk");
            out.archiveInspectionCandidate = ext == ".iso" || ext == ".img";
        }
        else if (StartsWithBytes(header, { '%', 'P', 'D', 'F', '-' }))
        {
            ApplyStrongType(out, "PDF document", "PDF document", "document");
        }
        else if (StartsWithBytes(header, { '{', '\\', 'r', 't', 'f' }))
        {
            ApplyStrongType(out, "RTF document", "RTF document", "document");
        }
        else if (StartsWithBytes(header, { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A }))
        {
            ApplyStrongType(out, "PNG image", "PNG image", "image");
        }
        else if (StartsWithBytes(header, { 0xFF, 0xD8, 0xFF }))
        {
            ApplyStrongType(out, "JPEG image", "JPEG image", "image");
        }
        else if (StartsWithBytes(header, { 'G', 'I', 'F', '8', '7', 'a' }) || StartsWithBytes(header, { 'G', 'I', 'F', '8', '9', 'a' }))
        {
            ApplyStrongType(out, "GIF image", "GIF image", "image");
        }
        else if (StartsWithBytes(header, { 'B', 'M' }))
        {
            ApplyStrongType(out, "Bitmap image", "Bitmap image", "image");
        }
        else if (StartsWithBytes(header, { 'I', 'I', 0x2A, 0x00 }) || StartsWithBytes(header, { 'M', 'M', 0x00, 0x2A }))
        {
            ApplyStrongType(out, "TIFF image", "TIFF image", "image");
        }
        else if (StartsWithBytes(header, { 0x00, 0x00, 0x01, 0x00 }))
        {
            ApplyStrongType(out, "Icon file", "Windows icon", "image");
        }
        else if (StartsWithBytes(header, { 0x00, 0x00, 0x02, 0x00 }))
        {
            ApplyStrongType(out, "Cursor file", "Windows cursor", "image");
        }
        else if (StartsWithBytes(header, { 'R', 'I', 'F', 'F' }) && MatchesBytesAt(header, 8, { 'W', 'A', 'V', 'E' }))
        {
            ApplyStrongType(out, "WAV audio", "WAV audio", "audio");
        }
        else if (StartsWithBytes(header, { 'R', 'I', 'F', 'F' }) && MatchesBytesAt(header, 8, { 'A', 'V', 'I', ' ' }))
        {
            ApplyStrongType(out, "AVI video", "AVI video", "video");
        }
        else if (StartsWithBytes(header, { 'R', 'I', 'F', 'F' }) && MatchesBytesAt(header, 8, { 'W', 'E', 'B', 'P' }))
        {
            ApplyStrongType(out, "WEBP image", "WEBP image", "image");
        }
        else if (StartsWithBytes(header, { 'O', 'g', 'g', 'S' }))
        {
            ApplyStrongType(out, ext == ".ogg" ? "Ogg media" : "Ogg media", "Ogg media", ext == ".ogv" ? "video" : "audio");
        }
        else if (StartsWithBytes(header, { 'f', 'L', 'a', 'C' }))
        {
            ApplyStrongType(out, "FLAC audio", "FLAC audio", "audio");
        }
        else if (StartsWithBytes(header, { 'M', 'T', 'h', 'd' }))
        {
            ApplyStrongType(out, "MIDI audio", "MIDI audio", "audio");
        }
        else if (StartsWithBytes(header, { 'I', 'D', '3' }) || (ext == ".mp3" && header.size() >= 2 && header[0] == 0xFF && (header[1] & 0xE0u) == 0xE0u))
        {
            ApplyStrongType(out, "MP3 audio", "MP3 audio", "audio");
        }
        else if (StartsWithBytes(header, { 0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11 }))
        {
            ApplyStrongType(out, ext == ".wma" ? "WMA audio" : "ASF media", ext == ".wma" ? "WMA audio" : "ASF media", ext == ".wma" ? "audio" : "video");
        }
        else if (header.size() >= 12 && MatchesBytesAt(header, 4, { 'f', 't', 'y', 'p' }))
        {
            const std::string brand = header.size() >= 12 ? std::string(reinterpret_cast<const char*>(header.data() + 8), reinterpret_cast<const char*>(header.data() + 12)) : std::string();
            const std::string lowerBrand = ToLowerCopy(brand);
            if (lowerBrand == "qt  ")
                ApplyStrongType(out, "QuickTime video", "QuickTime media", "video");
            else
                ApplyStrongType(out, ext == ".m4a" ? "M4A audio" : "MP4 video", ext == ".m4a" ? "M4A audio" : "ISO Base Media file", ext == ".m4a" ? "audio" : "video");
        }
        else if (StartsWithBytes(header, { 'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't', ' ', '3', 0x00 }))
        {
            ApplyStrongType(out, "SQLite database", "SQLite database", "database");
        }
        else if (StartsWithBytes(header, { 'I', 'T', 'S', 'F' }))
        {
            ApplyStrongType(out, "Compiled HTML Help", "CHM help file", "document");
        }
        else if (StartsWithBytes(header, { 0x00, 0x01, 0x00, 0x00 }) || StartsWithBytes(header, { 't', 't', 'c', 'f' }))
        {
            ApplyStrongType(out, "Font file", "TrueType font", "font");
        }
        else if (StartsWithBytes(header, { 'O', 'T', 'T', 'O' }))
        {
            ApplyStrongType(out, "Font file", "OpenType font", "font");
        }
        else if (StartsWithBytes(header, { 'w', 'O', 'F', 'F' }))
        {
            ApplyStrongType(out, "Font file", "WOFF font", "font");
        }
        else if (StartsWithBytes(header, { 'w', 'O', 'F', '2' }))
        {
            ApplyStrongType(out, "Font file", "WOFF2 font", "font");
        }
        else if (textLike)
        {
            std::string textFamily;
            const std::string textType = SpecificTypeFromText(ext, textPreview, textFamily);
            if (!textType.empty())
            {
                ApplyStrongType(out, textType, textType, textFamily.empty() ? "text" : textFamily);
                out.scriptLike = textFamily == "script";
            }
            else
            {
                ApplyStrongType(out, out.displayedType != "Generic file" ? out.displayedType : "Text document", "Plain text", "text");
            }
        }

        const std::string expectedFamily = ExpectedFamilyFromExtension(ext);
        if (!expectedFamily.empty() && out.familyTag != "unknown" && expectedFamily != out.familyTag)
        {
            if ((IsPassiveContentFamily(expectedFamily) && IsActiveContentFamily(out.familyTag)) ||
                (IsActiveContentFamily(expectedFamily) && IsPassiveContentFamily(out.familyTag)))
            {
                out.typeMismatchLikely = true;
            }
        }

        if (out.archiveInspectionCandidate)
            out.displayedType = out.displayedType == "Generic file" ? "Archive" : out.displayedType;

        return out;
    }

    std::string DetectRealFileType(const std::vector<unsigned char>& header,
                                   const std::string& extension,
                                   const std::string& printablePreview)
    {
        return DetectFileType("", extension, header, printablePreview).realType;
    }
}
