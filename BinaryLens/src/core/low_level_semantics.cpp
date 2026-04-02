#include "core/low_level_semantics.h"
#include "common/string_utils.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <sstream>

namespace
{
    // keep ratio math stable so feature summaries do not branch on divide-by-zero guards everywhere else.
    double SafeRatio(std::uint64_t value, std::uint64_t total)
    {
        if (total == 0)
            return 0.0;
        return static_cast<double>(value) / static_cast<double>(total);
    }

    // reuse a local entropy helper here because overlay windows are reasoned about as self-contained regions.
    double CalculateEntropy(const std::vector<std::uint8_t>& bytes)
    {
        if (bytes.empty())
            return 0.0;

        std::array<std::uint64_t, 256> counts = {};
        for (std::uint8_t value : bytes)
            ++counts[value];

        double entropy = 0.0;
        const double size = static_cast<double>(bytes.size());
        for (std::uint64_t count : counts)
        {
            if (count == 0)
                continue;
            const double p = static_cast<double>(count) / size;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    // coarse signature carving is enough for overlay hints; full format validation stays outside this layer.
    bool StartsWith(const std::vector<std::uint8_t>& bytes, std::initializer_list<std::uint8_t> prefix)
    {
        if (bytes.size() < prefix.size())
            return false;
        std::size_t i = 0;
        for (std::uint8_t value : prefix)
        {
            if (bytes[i++] != value)
                return false;
        }
        return true;
    }

    // case-folded token checks let the overlay profiler spot config and staging fragments without a heavy parser.
    bool ContainsAsciiCaseInsensitive(const std::vector<std::uint8_t>& bytes, const std::string& token)
    {
        if (bytes.empty() || token.empty() || bytes.size() < token.size())
            return false;

        const std::string lowerToken = bl::common::ToLowerCopy(token);
        for (std::size_t i = 0; i + lowerToken.size() <= bytes.size(); ++i)
        {
            bool match = true;
            for (std::size_t j = 0; j < lowerToken.size(); ++j)
            {
                unsigned char c = bytes[i + j];
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<unsigned char>(c | 0x20u);
                if (c != static_cast<unsigned char>(lowerToken[j]))
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return true;
        }
        return false;
    }

    std::string JoinLabels(const std::vector<std::string>& labels)
    {
        std::ostringstream oss;
        for (std::size_t i = 0; i < labels.size(); ++i)
        {
            if (i > 0)
                oss << ", ";
            oss << labels[i];
        }
        return oss.str();
    }
}

OpcodeSemanticSummary BuildOpcodeSemanticSummary(const bl::asmbridge::EntrypointAsmProfile& entryProfile,
                                                const bl::asmbridge::CodeSurfaceProfile& codeSurface,
                                                const bl::asmbridge::OpcodeFamilyProfile& opcodeFamilies)
{
    OpcodeSemanticSummary summary;

    // semantic tags bridge raw opcode buckets and the higher-level analyst language shown in reports.
    summary.branchHeavy = opcodeFamilies.controlTransferCount >= 5 || codeSurface.branchOpcodeCount >= 4;
    summary.stackSetupHeavy = opcodeFamilies.stackOperationCount >= 4 || codeSurface.stackFrameHintCount >= 2;
    summary.stubLike = summary.branchHeavy && opcodeFamilies.memoryTouchCount <= 3 && opcodeFamilies.stackOperationCount <= 3;
    summary.resolverLike = bl::asmbridge::HasFeature(entryProfile, bl::asmbridge::stub_call_pop) ||
                           bl::asmbridge::HasFeature(entryProfile, bl::asmbridge::stub_peb_access) ||
                           (opcodeFamilies.controlTransferCount >= 3 && opcodeFamilies.memoryTouchCount >= 3 && opcodeFamilies.compareTestCount >= 1);
    summary.decoderLike = bl::asmbridge::HasFeature(entryProfile, bl::asmbridge::stub_decoder_loop) ||
                          (opcodeFamilies.loopLikeCount >= 2 && opcodeFamilies.arithmeticLogicCount >= 4 && opcodeFamilies.memoryTouchCount >= 2);
    summary.loaderLike = bl::asmbridge::HasFeature(entryProfile, bl::asmbridge::stub_initial_jump) ||
                         bl::asmbridge::HasFeature(entryProfile, bl::asmbridge::stub_push_ret) ||
                         summary.resolverLike || summary.stubLike;

    const bool dispatcherLike = summary.branchHeavy && opcodeFamilies.compareTestCount >= 2 && opcodeFamilies.memoryTouchCount >= 2;
    const bool transformHeavy = opcodeFamilies.arithmeticLogicCount >= 5 && opcodeFamilies.loopLikeCount >= 1;
    const bool apiBootstrapLike = summary.resolverLike && (opcodeFamilies.memoryTouchCount >= 4 || codeSurface.ripRelativeHintCount > 0);

    if (summary.branchHeavy)
    {
        summary.tags.push_back("branch-heavy");
        summary.findings.push_back("control-transfer density is elevated in the profiled opening window");
    }
    if (summary.stubLike)
    {
        summary.tags.push_back("stub-like");
        summary.findings.push_back("opcode-family balance looks closer to a short dispatcher or trampoline than normal application prologue code");
    }
    if (summary.resolverLike)
    {
        summary.tags.push_back("resolver-like");
        summary.findings.push_back("opening window shows resolver-like balance between control transfer, memory touch, and comparison activity");
    }
    if (summary.decoderLike)
    {
        summary.tags.push_back("decoder-like");
        summary.findings.push_back("loop and arithmetic density suggest a potential decode or transform routine near the entrypoint");
    }
    if (summary.loaderLike)
    {
        summary.tags.push_back("loader-like");
        summary.findings.push_back("low-level entrypoint traits resemble a loader, bootstrap, or staged-dispatch opening sequence");
    }
    if (dispatcherLike)
    {
        summary.tags.push_back("dispatcher-like");
        summary.findings.push_back("control flow, compare density, and memory touch suggest a small dispatcher or routing stub");
    }
    if (transformHeavy)
    {
        summary.tags.push_back("transform-heavy");
        summary.findings.push_back("arithmetic and loop balance looks compatible with a short decode or transform phase");
    }
    if (apiBootstrapLike)
    {
        summary.tags.push_back("api-bootstrap-like");
        summary.findings.push_back("resolver traits plus memory-touch activity resemble early api bootstrap logic");
    }
    if (summary.stackSetupHeavy)
    {
        summary.tags.push_back("stack-setup-heavy");
        summary.findings.push_back("stack activity is higher than a minimal jump-stub profile");
    }
    if (opcodeFamilies.syscallInterruptCount > 0)
    {
        summary.tags.push_back("syscall-capable");
        summary.findings.push_back("interrupt or syscall-oriented instructions are already visible in the short entrypoint window");
    }
    if (opcodeFamilies.stringInstructionCount > 0)
    {
        summary.tags.push_back("string-instruction-activity");
        summary.findings.push_back("string-oriented instructions appear in the opening window, which can help small copy or decode stubs");
    }

    summary.summary = JoinLabels(summary.tags);
    return summary;
}

OverlayProfileResult AnalyzeOverlayBytes(const std::vector<std::uint8_t>& overlayBytes,
                                         std::uint64_t overlayBaseOffset)
{
    OverlayProfileResult result;
    if (overlayBytes.empty())
        return result;

    result.analyzed = true;

    // overlap adjacent windows so short payload islands or config fragments are less likely to fall on hard boundaries.
    constexpr std::size_t kWindow = 4096;
    constexpr std::size_t kStep = 2048;

    for (std::size_t offset = 0; offset < overlayBytes.size(); offset += kStep)
    {
        const std::size_t windowSize = (std::min)(kWindow, overlayBytes.size() - offset);
        if (windowSize < 256)
            break;

        std::vector<std::uint8_t> window(overlayBytes.begin() + static_cast<std::ptrdiff_t>(offset), overlayBytes.begin() + static_cast<std::ptrdiff_t>(offset + windowSize));
        ++result.sampledWindows;

        std::uint64_t printable = 0;
        std::uint64_t highBytes = 0;
        for (std::uint8_t value : window)
        {
            if ((value >= 32 && value <= 126) || value == '\n' || value == '\r' || value == '\t')
                ++printable;
            if (value & 0x80)
                ++highBytes;
        }

        const double entropy = CalculateEntropy(window);
        const double printableRatio = SafeRatio(printable, window.size());
        const double highRatio = SafeRatio(highBytes, window.size());
        result.maxEntropy = (std::max)(result.maxEntropy, entropy);

        const auto entryProfile = bl::asmbridge::ProfileEntrypointStub(window.data(), window.size());
        const auto codeSurface = bl::asmbridge::ProfileCodeSurface(window.data(), window.size());
        const auto opcodeFamilies = bl::asmbridge::ProfileOpcodeFamilies(window.data(), window.size());
        const auto semantics = BuildOpcodeSemanticSummary(entryProfile, codeSurface, opcodeFamilies);

        // each bucket here is intentionally broad because the goal is topology and staging hints, not format proof.
        const bool compressedLike = entropy >= 7.30 && printableRatio < 0.12 && highRatio > 0.45;
        const bool textLike = printableRatio >= 0.62 && entropy < 6.40;
        const bool codeLike = (entryProfile.suspiciousOpcodeScore >= 4 || semantics.loaderLike || semantics.stubLike) && printableRatio < 0.72;
        const bool urlLike = ContainsAsciiCaseInsensitive(window, "http://") || ContainsAsciiCaseInsensitive(window, "https://") || ContainsAsciiCaseInsensitive(window, "www.");

        if (compressedLike)
            ++result.compressedLikeWindows;
        if (textLike)
            ++result.textLikeWindows;
        if (codeLike)
            ++result.codeLikeWindows;
        if (urlLike)
            ++result.urlLikeWindows;

        if (StartsWith(window, {'M', 'Z'}) || StartsWith(window, {'P', 'K', 0x03, 0x04}) || StartsWith(window, {'%', 'P', 'D', 'F'}) || StartsWith(window, {'R', 'a', 'r', '!'}) || StartsWith(window, {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}))
        {
            ++result.embeddedHeaderHits;
            if (result.findings.size() < 8)
            {
                std::ostringstream oss;
                oss << "overlay region at offset " << (overlayBaseOffset + offset) << " starts with an embedded file-signature style header";
                result.findings.push_back(oss.str());
            }
        }

        if (codeLike && result.findings.size() < 8)
        {
            std::ostringstream oss;
            oss << "overlay region at offset " << (overlayBaseOffset + offset) << " looks code-like with "
                << (semantics.summary.empty() ? std::string("short execution-style traits") : semantics.summary);
            result.findings.push_back(oss.str());
        }
        else if (textLike && result.findings.size() < 8)
        {
            std::ostringstream oss;
            oss << "overlay region at offset " << (overlayBaseOffset + offset) << " is text-rich and may hold configuration or manifest-style content";
            result.findings.push_back(oss.str());
        }
        else if (compressedLike && result.findings.size() < 8)
        {
            std::ostringstream oss;
            oss << "overlay region at offset " << (overlayBaseOffset + offset) << " is compression-like with entropy " << std::fixed << std::setprecision(2) << entropy;
            result.findings.push_back(oss.str());
        }
    }

    // the summary line should read like a region map rather than a raw counter dump.
    std::vector<std::string> summaryLabels;
    if (result.codeLikeWindows > 0)
        summaryLabels.push_back("code-like windows");
    if (result.textLikeWindows > 0)
        summaryLabels.push_back("text-rich windows");
    if (result.compressedLikeWindows > 0)
        summaryLabels.push_back("compressed-like windows");
    if (result.embeddedHeaderHits > 0)
        summaryLabels.push_back("embedded header hits");
    if (result.urlLikeWindows > 0)
        summaryLabels.push_back("url-bearing windows");

    if (!summaryLabels.empty())
        result.summary = JoinLabels(summaryLabels);

    return result;
}
