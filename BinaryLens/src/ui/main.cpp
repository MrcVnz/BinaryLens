#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <uxtheme.h>

#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <cstdint>
#include <cstring>
#include <fstream>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "UxTheme.lib")

#include "core/analysis_control.h"
#include "core/analysis_engine.h"
#include "scanners/file_scanner.h"
// win32 ui flow for input handling, progress updates, theming, and report presentation.

#define IDC_URL_INPUT       101
#define IDC_SELECT_FILE     102
#define IDC_ANALYZE         103
#define IDC_RESULT_BOX      104
#define IDC_FILE_LABEL      105
#define IDC_PROGRESS_BAR    106
#define IDC_CANCEL          107
#define IDC_STATUS_LABEL    108
#define IDC_TITLE_LABEL     109
#define IDC_SUBTITLE_LABEL  110
#define IDC_RESULTS_LABEL   111
#define IDC_INPUT_LABEL     112
#define IDC_HEADER_PANEL    113
#define IDC_TOP_PANEL       114
#define IDC_ACTION_PANEL    115
#define IDC_RESULT_PANEL    116
#define IDC_THEME_TOGGLE    117
#define IDC_EXPORT          118
#define IDC_COPY            119
#define IDC_VIEW_TOGGLE     120
#define IDC_EXPORT_IOC      121

#define WM_APP_PROGRESS     (WM_APP + 1)
#define WM_APP_RESULT       (WM_APP + 2)

struct UiTextPayload
{
    std::string text;
    std::string analystText;
    std::string iocText;
    std::string jsonText;
    int percent = 0;
    std::string statusLine;
};

struct AppFonts
{
    HFONT title = NULL;
    HFONT subtitle = NULL;
    HFONT body = NULL;
    HFONT bodyBold = NULL;
    HFONT mono = NULL;
};

struct LayoutMetrics
{
    int margin = 16;
    int gap = 12;
    int headerHeight = 96;
    int panelGap = 10;
    int inputHeight = 42;
    int buttonHeight = 40;
    int buttonWidth = 136;
    int selectWidth = 184;
    int themeButtonWidth = 134;
    int fileLabelHeight = 20;
    int sectionTitleHeight = 20;
    int progressHeight = 12;
    int statusHeight = 18;
    int minResultHeight = 390;
};

struct ThemeColors
{
    COLORREF windowBg = RGB(17, 19, 24);
    COLORREF panelBg = RGB(24, 27, 34);
    COLORREF panelBorder = RGB(42, 48, 62);
    COLORREF inputBg = RGB(14, 16, 22);
    COLORREF inputBorder = RGB(58, 66, 84);
    COLORREF accent = RGB(43, 116, 255);
    COLORREF accentHover = RGB(64, 132, 255);
    COLORREF textPrimary = RGB(236, 240, 248);
    COLORREF textMuted = RGB(148, 157, 176);
    COLORREF textDim = RGB(114, 123, 140);
    COLORREF buttonSecondary = RGB(33, 37, 46);
    COLORREF resultBg = RGB(12, 14, 19);
};

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void OpenFilePicker(HWND hwnd);

HWND g_hTitleLabel = NULL;
HWND g_hSubtitleLabel = NULL;
HWND g_hInputLabel = NULL;
HWND g_hUrlInput = NULL;
HWND g_hSelectFileButton = NULL;
HWND g_hFileLabel = NULL;
HWND g_hAnalyzeButton = NULL;
HWND g_hCancelButton = NULL;
HWND g_hResultsLabel = NULL;
HWND g_hProgressBar = NULL;
HWND g_hStatusLabel = NULL;
HWND g_hResultBox = NULL;
HWND g_hThemeToggleButton = NULL;
HWND g_hExportButton = NULL;
HWND g_hCopyButton = NULL;
HWND g_hViewToggleButton = NULL;
HWND g_hExportIocButton = NULL;
AppFonts g_fonts;
ThemeColors g_colors;
std::string g_selectedFilePath;
std::string g_lastReportText;
std::string g_lastReportJson;
std::string g_lastAnalystReportText;
std::string g_lastIocReportText;
bool g_analystView = false;
bool g_analysisRunning = false;
bool g_darkTheme = true;
LayoutMetrics g_metrics;
HBRUSH g_windowBrush = NULL;
HBRUSH g_panelBrush = NULL;
HBRUSH g_inputBrush = NULL;
HBRUSH g_resultBrush = NULL;
HBRUSH g_progressBgBrush = NULL;

// global ui state, theme resources, and helper routines shared by the window procedure.
namespace
{
    // initializes progress widgets used by long-running scans and cancellation feedback.
void ConfigureProgressBar();
    // computes control geometry dynamically so the result view can expand when status widgets collapse.
void LayoutControls(HWND hwnd);
    std::string GetActiveReportText();

    bool WriteTextFile(const std::string& path, const std::string& content)
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out)
            return false;
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        return out.good();
    }

    // reuse one save dialog helper for report, json, and ioc export paths.
    std::string GetSaveReportPath(HWND hwnd, bool jsonFormat)
    {
        char fileName[MAX_PATH] = "";
        OPENFILENAMEA ofn = {};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hwnd;
        ofn.lpstrFile = fileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrDefExt = jsonFormat ? "json" : "txt";
        ofn.lpstrFilter = jsonFormat
            ? "JSON Report (*.json)\0*.json\0All Files\0*.*\0"
            : "Text Report (*.txt)\0*.txt\0All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
        if (!GetSaveFileNameA(&ofn))
            return "";
        return fileName;
    }

    // serializes the currently visible report to disk in text or json form.
void ExportLatestReport(HWND hwnd, bool jsonFormat)
    {
        const std::string content = jsonFormat ? g_lastReportJson : GetActiveReportText();
        if (content.empty())
        {
            MessageBoxA(hwnd, jsonFormat ? "No JSON report is available for the last analysis." : "Run an analysis first before exporting a report.", "BinaryLens", MB_OK | MB_ICONINFORMATION);
            return;
        }

        const std::string path = GetSaveReportPath(hwnd, jsonFormat);
        if (path.empty())
            return;

        if (!WriteTextFile(path, content))
        {
            MessageBoxA(hwnd, "Could not save the report to the selected location.", "BinaryLens", MB_OK | MB_ICONERROR);
            return;
        }

        std::string message = "Report saved to:\n" + path;
        MessageBoxA(hwnd, message.c_str(), "BinaryLens", MB_OK | MB_ICONINFORMATION);
    }

    // clipboard export uses the active view so analyst mode copies analyst text directly.
    bool CopyTextToClipboard(HWND hwnd, const std::string& text)
    {
        if (text.empty())
            return false;
        if (!OpenClipboard(hwnd))
            return false;

        EmptyClipboard();
        const SIZE_T bytes = text.size() + 1;
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (!hMem)
        {
            CloseClipboard();
            return false;
        }

        void* ptr = GlobalLock(hMem);
        if (!ptr)
        {
            GlobalFree(hMem);
            CloseClipboard();
            return false;
        }

        memcpy(ptr, text.c_str(), bytes);
        GlobalUnlock(hMem);

        if (!SetClipboardData(CF_TEXT, hMem))
        {
            GlobalFree(hMem);
            CloseClipboard();
            return false;
        }

        CloseClipboard();
        return true;
    }

    void RefreshViewToggleLabel()
    {
        if (g_hViewToggleButton)
            SetWindowTextA(g_hViewToggleButton, g_analystView ? "User View" : "Analyst View");
    }

    std::string GetActiveReportText()
    {
        if (g_analystView && !g_lastAnalystReportText.empty())
            return g_lastAnalystReportText;
        return g_lastReportText;
    }

    void RefreshDisplayedReport()
    {
        const std::string active = GetActiveReportText();
        if (!active.empty() && g_hResultBox)
            SetWindowTextA(g_hResultBox, active.c_str());
    }

    void RefreshReportActionsState()
    {
        const BOOL enabled = (!g_analysisRunning && !g_lastReportText.empty()) ? TRUE : FALSE;
        if (g_hExportButton)
            EnableWindow(g_hExportButton, enabled);
        if (g_hCopyButton)
            EnableWindow(g_hCopyButton, enabled);
        if (g_hViewToggleButton)
            EnableWindow(g_hViewToggleButton, enabled);
        if (g_hExportIocButton)
            EnableWindow(g_hExportIocButton, (!g_analysisRunning && !g_lastIocReportText.empty()) ? TRUE : FALSE);
        RefreshViewToggleLabel();
    }

    // keep both palettes together so theme switches only swap color structs and brushes.
    ThemeColors MakeDarkTheme()
    {
        ThemeColors c;
        c.windowBg = RGB(14, 17, 23);
        c.panelBg = RGB(20, 25, 33);
        c.panelBorder = RGB(49, 59, 79);
        c.inputBg = RGB(11, 14, 20);
        c.inputBorder = RGB(70, 83, 108);
        c.accent = RGB(48, 116, 242);
        c.accentHover = RGB(70, 132, 255);
        c.textPrimary = RGB(239, 244, 251);
        c.textMuted = RGB(171, 181, 199);
        c.textDim = RGB(123, 135, 156);
        c.buttonSecondary = RGB(28, 35, 46);
        c.resultBg = RGB(7, 10, 15);
        return c;
    }

    ThemeColors MakeLightTheme()
    {
        ThemeColors c;
        c.windowBg = RGB(239, 243, 249);
        c.panelBg = RGB(251, 252, 254);
        c.panelBorder = RGB(203, 212, 226);
        c.inputBg = RGB(255, 255, 255);
        c.inputBorder = RGB(154, 166, 186);
        c.accent = RGB(32, 94, 220);
        c.accentHover = RGB(50, 108, 228);
        c.textPrimary = RGB(20, 28, 40);
        c.textMuted = RGB(86, 96, 114);
        c.textDim = RGB(129, 139, 156);
        c.buttonSecondary = RGB(233, 238, 246);
        c.resultBg = RGB(255, 255, 255);
        return c;
    }

    std::string TruncateMiddle(const std::string& text, size_t maxLen = 104)
    {
        if (text.size() <= maxLen)
            return text;
        if (maxLen < 12)
            return text.substr(0, maxLen);
        const size_t left = (maxLen - 3) / 2;
        const size_t right = maxLen - 3 - left;
        return text.substr(0, left) + "..." + text.substr(text.size() - right);
    }

    // the ui mixes regular and mono fonts so reports stay readable without losing alignment.
    HFONT CreateSegoeFont(int height, int weight = FW_NORMAL, bool mono = false)
    {
        return CreateFontA(
            -height, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, mono ? "Cascadia Mono" : "Segoe UI");
    }

    void CreateAppFonts()
    {
        g_fonts.title = CreateSegoeFont(30, FW_BOLD);
        g_fonts.subtitle = CreateSegoeFont(12, FW_NORMAL);
        g_fonts.body = CreateSegoeFont(12, FW_NORMAL);
        g_fonts.bodyBold = CreateSegoeFont(12, FW_SEMIBOLD);
        g_fonts.mono = CreateSegoeFont(12, FW_NORMAL, true);
    }

    void DeleteAppFonts()
    {
        if (g_fonts.title) DeleteObject(g_fonts.title);
        if (g_fonts.subtitle) DeleteObject(g_fonts.subtitle);
        if (g_fonts.body) DeleteObject(g_fonts.body);
        if (g_fonts.bodyBold) DeleteObject(g_fonts.bodyBold);
        if (g_fonts.mono) DeleteObject(g_fonts.mono);
        g_fonts = {};
    }

    void CreateThemeBrushes()
    {
        g_windowBrush = CreateSolidBrush(g_colors.windowBg);
        g_panelBrush = CreateSolidBrush(g_colors.panelBg);
        g_inputBrush = CreateSolidBrush(g_colors.inputBg);
        g_resultBrush = CreateSolidBrush(g_colors.resultBg);
        g_progressBgBrush = CreateSolidBrush(g_colors.panelBg);
    }

    void DeleteThemeBrushes()
    {
        if (g_windowBrush) DeleteObject(g_windowBrush);
        if (g_panelBrush) DeleteObject(g_panelBrush);
        if (g_inputBrush) DeleteObject(g_inputBrush);
        if (g_resultBrush) DeleteObject(g_resultBrush);
        if (g_progressBgBrush) DeleteObject(g_progressBgBrush);
        g_windowBrush = g_panelBrush = g_inputBrush = g_resultBrush = g_progressBgBrush = NULL;
    }

    // reapplies colors and brushes so both themes stay visually consistent across controls.
// repaint child controls after a theme flip to avoid stale system colors.
void RefreshTheme(HWND hwnd)
    {
        DeleteThemeBrushes();
        CreateThemeBrushes();
        ConfigureProgressBar();
        const char* toggleLabel = g_darkTheme ? "Light Theme" : "Dark Theme";
        if (g_hThemeToggleButton)
            SetWindowTextA(g_hThemeToggleButton, toggleLabel);
        InvalidateRect(hwnd, nullptr, TRUE);
        if (g_hUrlInput) InvalidateRect(g_hUrlInput, nullptr, TRUE);
        if (g_hResultBox) InvalidateRect(g_hResultBox, nullptr, TRUE);
        if (g_hFileLabel) InvalidateRect(g_hFileLabel, nullptr, TRUE);
        if (g_hStatusLabel) InvalidateRect(g_hStatusLabel, nullptr, TRUE);
        if (g_hTitleLabel) InvalidateRect(g_hTitleLabel, nullptr, TRUE);
        if (g_hSubtitleLabel) InvalidateRect(g_hSubtitleLabel, nullptr, TRUE);
        if (g_hInputLabel) InvalidateRect(g_hInputLabel, nullptr, TRUE);
        if (g_hResultsLabel) InvalidateRect(g_hResultsLabel, nullptr, TRUE);
        RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
    }

    void ToggleTheme(HWND hwnd)
    {
        g_darkTheme = !g_darkTheme;
        g_colors = g_darkTheme ? MakeDarkTheme() : MakeLightTheme();
        RefreshTheme(hwnd);
    }

    std::string TrimCopy(const std::string& value)
    {
        const auto begin = value.find_first_not_of(" \t\n");
        if (begin == std::string::npos)
            return "";
        const auto end = value.find_last_not_of(" \t\n");
        return value.substr(begin, end - begin + 1);
    }

    void ApplyFont(HWND hwnd, HFONT font)
    {
        if (hwnd && font)
            SendMessageA(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }

    void ApplyControlFonts()
    {
        ApplyFont(g_hTitleLabel, g_fonts.title);
        ApplyFont(g_hSubtitleLabel, g_fonts.subtitle);
        ApplyFont(g_hInputLabel, g_fonts.bodyBold);
        ApplyFont(g_hUrlInput, g_fonts.body);
        ApplyFont(g_hSelectFileButton, g_fonts.bodyBold);
        ApplyFont(g_hFileLabel, g_fonts.subtitle);
        ApplyFont(g_hAnalyzeButton, g_fonts.bodyBold);
        ApplyFont(g_hCancelButton, g_fonts.bodyBold);
        ApplyFont(g_hResultsLabel, g_fonts.bodyBold);
        ApplyFont(g_hStatusLabel, g_fonts.subtitle);
        ApplyFont(g_hResultBox, g_fonts.mono);
        ApplyFont(g_hThemeToggleButton, g_fonts.bodyBold);
        ApplyFont(g_hExportButton, g_fonts.bodyBold);
        ApplyFont(g_hCopyButton, g_fonts.bodyBold);
        ApplyFont(g_hViewToggleButton, g_fonts.bodyBold);
        ApplyFont(g_hExportIocButton, g_fonts.bodyBold);
    }

    void ApplyEditMargins()
    {
        const LPARAM margins = MAKELPARAM(12, 12);
        if (g_hUrlInput)
            SendMessageA(g_hUrlInput, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, margins);
        if (g_hResultBox)
            SendMessageA(g_hResultBox, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, margins);
    }

    void ConfigureProgressBar()
    {
        SendMessageA(g_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageA(g_hProgressBar, PBM_SETBKCOLOR, 0, g_colors.panelBg);
        SendMessageA(g_hProgressBar, PBM_SETBARCOLOR, 0, g_colors.accent);
    }

    void SetProgressVisible(bool visible)
    {
        ShowWindow(g_hProgressBar, visible ? SW_SHOW : SW_HIDE);
        ShowWindow(g_hStatusLabel, visible ? SW_SHOW : SW_HIDE);
        if (g_hResultBox)
            LayoutControls(GetParent(g_hResultBox));
    }

    std::string FormatEtaText(int etaSeconds)
    {
        if (etaSeconds < 0)
            return "Calculating...";
        const int hours = etaSeconds / 3600;
        const int minutes = (etaSeconds % 3600) / 60;
        const int seconds = etaSeconds % 60;
        std::ostringstream oss;
        if (hours > 0)
            oss << hours << "h ";
        if (hours > 0 || minutes > 0)
            oss << minutes << "m ";
        oss << seconds << "s";
        return oss.str();
    }

    // status text mirrors the pipeline stage and heavy-file throughput without exposing internals.
    std::string BuildStatusLine(const AnalysisProgress& p)
    {
        std::ostringstream speedStream;
        speedStream.setf(std::ios::fixed);
        speedStream.precision(2);
        speedStream << p.speedMBps;

        std::string line = p.stage;
        if (!p.detail.empty())
            line += " | " + p.detail;
        if (p.totalBytes > 0)
        {
            line += " | ";
            line += std::to_string(p.percent) + "%";
            line += " | ";
            line += FormatFileSize(p.processedBytes) + " / " + FormatFileSize(p.totalBytes);
        }
        if (p.chunkCount > 0)
            line += " | Chunk " + std::to_string(p.chunkIndex) + "/" + std::to_string(p.chunkCount);
        line += " | " + speedStream.str() + " MB/s";
        line += " | ETA " + FormatEtaText(p.etaSeconds);
        return line;
    }

    std::string BuildProgressText(const AnalysisProgress& p)
    {
        auto formatBytes = [](std::uint64_t value) {
            return FormatFileSize(value) + " (" + std::to_string(value) + " bytes)";
            };
        std::ostringstream speedStream;
        speedStream.setf(std::ios::fixed);
        speedStream.precision(2);
        speedStream << p.speedMBps;

        std::string out = "BinaryLens Scan Result\r\n\r\n";
        out += std::string("Status: ") + (p.cancellationRequested ? "Cancellation requested..." : "Analysis in progress...") + "\r\n";
        out += "Mode: " + p.mode + "\r\n";
        out += "Stage: " + p.stage + "\r\n";
        out += "Detail: " + p.detail + "\r\n";
        out += "Progress: " + std::to_string(p.percent) + "%\r\n";
        if (p.totalBytes > 0)
            out += "Processed: " + formatBytes(p.processedBytes) + " / " + formatBytes(p.totalBytes) + "\r\n";
        else
            out += "Processed: Collecting metadata...\r\n";
        if (p.chunkCount > 0)
            out += "Chunk: " + std::to_string(p.chunkIndex) + " / " + std::to_string(p.chunkCount) + "\r\n";
        out += "Speed: " + speedStream.str() + " MB/s\r\n";
        out += "ETA: " + FormatEtaText(p.etaSeconds) + "\r\n";
        out += "\r\nNotice: Large files can take several minutes, but the status above shows what is executing right now.\r\n";
        return out;
    }

    void ResetSelectedFileUI()
    {
        g_selectedFilePath.clear();
        SetWindowTextA(g_hFileLabel, "Selected file: None");
    }

    void ResetUrlUI()
    {
        SetWindowTextA(g_hUrlInput, "");
    }

    // lock conflicting controls while work is active so file and url modes cannot overlap.
    void UpdateUiForRunningState(bool running)
    {
        g_analysisRunning = running;
        EnableWindow(g_hAnalyzeButton, running ? FALSE : TRUE);
        EnableWindow(g_hCancelButton, running ? TRUE : FALSE);
        EnableWindow(g_hSelectFileButton, running ? FALSE : TRUE);
        EnableWindow(g_hUrlInput, running ? FALSE : TRUE);
        EnableWindow(g_hThemeToggleButton, TRUE);
        RefreshReportActionsState();

        if (running)
        {
            SetProgressVisible(true);
            SendMessageA(g_hProgressBar, PBM_SETPOS, 0, 0);
            SetWindowTextA(g_hStatusLabel, "Preparing full analysis...");
        }
        else
        {
            SendMessageA(g_hProgressBar, PBM_SETPOS, 0, 0);
            SetWindowTextA(g_hStatusLabel, "Ready.");
            SetProgressVisible(false);
        }
        InvalidateRect(GetParent(g_hAnalyzeButton), nullptr, TRUE);
    }

    void LayoutControls(HWND hwnd)
    {
        RECT rc{};
        GetClientRect(hwnd, &rc);
        const int margin = g_metrics.margin;
        const int width = rc.right - rc.left;
        const int height = rc.bottom - rc.top;
        const int contentWidth = width - (margin * 2);

        int y = margin;
        const int themeWidth = g_metrics.themeButtonWidth;
        MoveWindow(g_hTitleLabel, margin + 18, y + 14, contentWidth - 36 - themeWidth - g_metrics.gap, 34, TRUE);
        MoveWindow(g_hSubtitleLabel, margin + 18, y + 48, contentWidth - 36 - themeWidth - g_metrics.gap, 22, TRUE);
        MoveWindow(g_hThemeToggleButton, rc.right - margin - 18 - themeWidth, y + 18, themeWidth, 34, TRUE);
        y += g_metrics.headerHeight + g_metrics.panelGap;

        MoveWindow(g_hInputLabel, margin + 18, y + 12, 140, 20, TRUE);
        const int inputY = y + 38;
        const int selectWidth = g_metrics.selectWidth;
        const int inputWidth = contentWidth - 36 - selectWidth - g_metrics.gap;
        MoveWindow(g_hUrlInput, margin + 18, inputY, inputWidth, g_metrics.inputHeight, TRUE);
        MoveWindow(g_hSelectFileButton, margin + 18 + inputWidth + g_metrics.gap, inputY, selectWidth, g_metrics.inputHeight, TRUE);
        MoveWindow(g_hFileLabel, margin + 18, inputY + g_metrics.inputHeight + 10, contentWidth - 36, g_metrics.fileLabelHeight, TRUE);
        y += 116;

        const int actionInnerWidth = contentWidth - 36;
        const int visibleButtons = 6;
        const int smallButtonWidth = max(118, (actionInnerWidth - ((visibleButtons - 1) * g_metrics.gap)) / visibleButtons);
        int buttonX = margin + 18;
        MoveWindow(g_hAnalyzeButton, buttonX, y + 10, smallButtonWidth, g_metrics.buttonHeight, TRUE);
        buttonX += smallButtonWidth + g_metrics.gap;
        MoveWindow(g_hCancelButton, buttonX, y + 10, smallButtonWidth, g_metrics.buttonHeight, TRUE);
        buttonX += smallButtonWidth + g_metrics.gap;
        MoveWindow(g_hExportButton, buttonX, y + 10, smallButtonWidth, g_metrics.buttonHeight, TRUE);
        buttonX += smallButtonWidth + g_metrics.gap;
        MoveWindow(g_hCopyButton, buttonX, y + 10, smallButtonWidth, g_metrics.buttonHeight, TRUE);
        buttonX += smallButtonWidth + g_metrics.gap;
        MoveWindow(g_hViewToggleButton, buttonX, y + 10, smallButtonWidth, g_metrics.buttonHeight, TRUE);
        buttonX += smallButtonWidth + g_metrics.gap;
        MoveWindow(g_hExportIocButton, buttonX, y + 10, smallButtonWidth, g_metrics.buttonHeight, TRUE);
        y += 60 + g_metrics.panelGap;

        MoveWindow(g_hResultsLabel, margin + 18, y + 12, 140, g_metrics.sectionTitleHeight, TRUE);
        const int progressY = y + 42;
        MoveWindow(g_hProgressBar, margin + 18, progressY, contentWidth - 36, g_metrics.progressHeight, TRUE);
        MoveWindow(g_hStatusLabel, margin + 18, progressY + g_metrics.progressHeight + 8, contentWidth - 36, g_metrics.statusHeight, TRUE);
        const bool progressVisible = IsWindowVisible(g_hProgressBar) == TRUE || IsWindowVisible(g_hStatusLabel) == TRUE;
        const int resultY = progressVisible ? (progressY + g_metrics.progressHeight + g_metrics.statusHeight + 22) : (y + 42);
        const int resultHeight = max(g_metrics.minResultHeight, height - resultY - margin - 18);
        MoveWindow(g_hResultBox, margin + 18, resultY, contentWidth - 36, resultHeight, TRUE);
    }

    void DrawPanel(HDC hdc, const RECT& rc)
    {
        HBRUSH brush = CreateSolidBrush(g_colors.panelBg);
        FillRect(hdc, &rc, brush);
        DeleteObject(brush);
        HPEN pen = CreatePen(PS_SOLID, 1, g_colors.panelBorder);
        HPEN oldPen = (HPEN)SelectObject(hdc, pen);
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(HOLLOW_BRUSH));
        Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
        RECT accentStrip = { rc.left + 1, rc.top + 1, rc.right - 1, rc.top + 3 };
        HBRUSH accentBrush = CreateSolidBrush(g_darkTheme ? RGB(36, 73, 150) : RGB(183, 208, 250));
        FillRect(hdc, &accentStrip, accentBrush);
        DeleteObject(accentBrush);
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(pen);
    }

    // owner-draw keeps both themes visually consistent with the custom cards.
    void DrawButton(const DRAWITEMSTRUCT* dis)
    {
        const UINT id = dis->CtlID;
        const bool enabled = (dis->itemState & ODS_DISABLED) == 0;
        const bool selected = (dis->itemState & ODS_SELECTED) != 0;
        const bool primary = id == IDC_ANALYZE || id == IDC_SELECT_FILE;
        const COLORREF disabledBg = g_darkTheme ? RGB(46, 50, 60) : RGB(216, 221, 229);
        const COLORREF secondaryPressed = g_darkTheme ? RGB(44, 49, 61) : RGB(210, 218, 229);
        const COLORREF bg = !enabled ? disabledBg : (primary ? (selected ? g_colors.accentHover : g_colors.accent) : (selected ? secondaryPressed : g_colors.buttonSecondary));
        const COLORREF border = primary ? bg : (g_darkTheme ? RGB(55, 62, 78) : RGB(178, 188, 202));
        const COLORREF text = !enabled ? g_colors.textDim : (primary ? RGB(255, 255, 255) : g_colors.textPrimary);

        HBRUSH brush = CreateSolidBrush(bg);
        FillRect(dis->hDC, &dis->rcItem, brush);
        DeleteObject(brush);
        HPEN pen = CreatePen(PS_SOLID, 1, border);
        HPEN oldPen = (HPEN)SelectObject(dis->hDC, pen);
        HBRUSH oldBrush = (HBRUSH)SelectObject(dis->hDC, GetStockObject(HOLLOW_BRUSH));
        Rectangle(dis->hDC, dis->rcItem.left, dis->rcItem.top, dis->rcItem.right, dis->rcItem.bottom);
        SelectObject(dis->hDC, oldBrush);
        SelectObject(dis->hDC, oldPen);
        DeleteObject(pen);

        char textBuf[128]{};
        GetWindowTextA(dis->hwndItem, textBuf, sizeof(textBuf));
        SetBkMode(dis->hDC, TRANSPARENT);
        SetTextColor(dis->hDC, text);
        HFONT oldFont = (HFONT)SelectObject(dis->hDC, g_fonts.bodyBold);
        RECT textRc = dis->rcItem;
        DrawTextA(dis->hDC, textBuf, -1, &textRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(dis->hDC, oldFont);
    }

    // launches the worker thread, streams progress back to the ui, and stores the latest report payload.
    void StartAnalysis(HWND hwnd, const std::string& targetPath)
    {
        ResetAnalysisCancellation();
        UpdateUiForRunningState(true);
        SetWindowTextA(g_hResultBox, "BinaryLens Scan Result\r\n\r\nStatus: Analysis in progress...\r\nPlease wait while BinaryLens processes the target.");
        SendMessageA(g_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageA(g_hProgressBar, PBM_SETPOS, 0, 0);
        SetWindowTextA(g_hStatusLabel, "Initializing full analysis...");

        // the worker thread posts plain text payloads back through window messages.
        std::thread([hwnd, targetPath]() {
            AnalysisReportData report = RunFileAnalysisDetailed(targetPath, [hwnd, lastUiTick = 0ULL, lastPercent = -1, lastLine = std::string()](const AnalysisProgress& progress) mutable {
                const std::string statusLine = BuildStatusLine(progress);
                const ULONGLONG now = GetTickCount64();
                const bool stageChanged = statusLine != lastLine;
                const bool percentChanged = progress.percent != lastPercent;
                const bool shouldPost = progress.percent >= 100 || stageChanged || percentChanged || (now - lastUiTick) >= 150;
                if (!shouldPost)
                    return;

                lastUiTick = now;
                lastPercent = progress.percent;
                lastLine = statusLine;
                auto payload = new UiTextPayload{ std::string(), std::string(), std::string(), std::string(), progress.percent, statusLine };
                PostMessageA(hwnd, WM_APP_PROGRESS, 0, reinterpret_cast<LPARAM>(payload));
                });

            auto payload = new UiTextPayload{ report.textReport, report.analystTextReport, report.iocTextReport, report.jsonReport, 100, "Analysis complete." };
            PostMessageA(hwnd, WM_APP_RESULT, 0, reinterpret_cast<LPARAM>(payload));
            }).detach();
    }
}

// creates the main window, registers controls, and drives the win32 message loop.
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);

    g_colors = MakeDarkTheme();
    CreateAppFonts();
    CreateThemeBrushes();

    const char CLASS_NAME[] = "BinaryLensWindowClass";
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = g_windowBrush;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;

    RegisterClassExA(&wc);

    HWND hwnd = CreateWindowExA(
        0, CLASS_NAME, "BinaryLens", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1120, 820, NULL, NULL, hInstance, NULL);

    if (!hwnd)
        return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessageA(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return static_cast<int>(msg.wParam);
}

void OpenFilePicker(HWND hwnd)
{
    char fileName[MAX_PATH] = "";
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter =
        "All Files\0*.*\0"
        "Executables\0*.exe;*.dll;*.scr;*.bat;*.cmd;*.sys;*.ocx\0"
        "Installers\0*.msi\0"
        "Archives\0*.zip;*.rar;*.7z\0"
        "Scripts\0*.ps1;*.js;*.vbs;*.hta\0"
        "Text Files\0*.txt;*.log;*.md\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn))
    {
        g_selectedFilePath = fileName;
        ResetUrlUI();
        std::string label = "Selected file: " + TruncateMiddle(g_selectedFilePath);
        SetWindowTextA(g_hFileLabel, label.c_str());
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CREATE:
    {
        g_hTitleLabel = CreateWindowA("STATIC", "BinaryLens", WS_VISIBLE | WS_CHILD,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_TITLE_LABEL), NULL, NULL);
        g_hSubtitleLabel = CreateWindowA("STATIC",
            "Fast file, URL, and IP analysis with tuned confidence, evasion signals, and cleaner investigation output.",
            WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SUBTITLE_LABEL), NULL, NULL);
        g_hInputLabel = CreateWindowA("STATIC", "Target", WS_VISIBLE | WS_CHILD,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_INPUT_LABEL), NULL, NULL);
        g_hThemeToggleButton = CreateWindowA("BUTTON", "Light Theme", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_THEME_TOGGLE), NULL, NULL);

        g_hUrlInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0,
            hwnd, reinterpret_cast<HMENU>(IDC_URL_INPUT), NULL, NULL);

        g_hSelectFileButton = CreateWindowA("BUTTON", "Select File", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SELECT_FILE), NULL, NULL);
        g_hFileLabel = CreateWindowA("STATIC", "Selected file: None", WS_VISIBLE | WS_CHILD,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_FILE_LABEL), NULL, NULL);
        g_hAnalyzeButton = CreateWindowA("BUTTON", "Analyze", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_ANALYZE), NULL, NULL);
        g_hCancelButton = CreateWindowA("BUTTON", "Cancel", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_CANCEL), NULL, NULL);
        g_hExportButton = CreateWindowA("BUTTON", "Export Report", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EXPORT), NULL, NULL);
        g_hCopyButton = CreateWindowA("BUTTON", "Copy Report", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_COPY), NULL, NULL);
        g_hViewToggleButton = CreateWindowA("BUTTON", "Analyst View", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_VIEW_TOGGLE), NULL, NULL);
        g_hExportIocButton = CreateWindowA("BUTTON", "Export IOCs", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EXPORT_IOC), NULL, NULL);
        EnableWindow(g_hCancelButton, FALSE);
        EnableWindow(g_hExportButton, FALSE);
        EnableWindow(g_hCopyButton, FALSE);
        EnableWindow(g_hViewToggleButton, FALSE);
        EnableWindow(g_hExportIocButton, FALSE);

        g_hResultsLabel = CreateWindowA("STATIC", "Results", WS_VISIBLE | WS_CHILD,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_RESULTS_LABEL), NULL, NULL);

        g_hProgressBar = CreateWindowExA(0, PROGRESS_CLASSA, "", WS_CHILD,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PROGRESS_BAR), NULL, NULL);
        ConfigureProgressBar();

        g_hStatusLabel = CreateWindowA("STATIC", "Ready.", WS_CHILD,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STATUS_LABEL), NULL, NULL);

        g_hResultBox = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT",
            "BinaryLens Scan Result\r\n\r\nStatus: Waiting for a file, URL, or IP target.",
            WS_VISIBLE | WS_CHILD | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_RESULT_BOX), NULL, NULL);

        ApplyControlFonts();
        ApplyEditMargins();
        SendMessageW(g_hUrlInput, EM_SETCUEBANNER, FALSE, reinterpret_cast<LPARAM>(L"Paste a URL or an IP like 172.66.0.227, or select a file for full analysis"));
        SetProgressVisible(false);
        LayoutControls(hwnd);
        return 0;
    }
    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
        if (mmi)
        {
            mmi->ptMinTrackSize.x = 1120;
            mmi->ptMinTrackSize.y = 800;
        }
        return 0;
    }

    case WM_SIZE:
        LayoutControls(hwnd);
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;

    case WM_DRAWITEM:
        DrawButton(reinterpret_cast<const DRAWITEMSTRUCT*>(lParam));
        return TRUE;

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        HWND ctrl = reinterpret_cast<HWND>(lParam);
        if (ctrl == g_hResultBox)
        {
            SetBkColor(hdc, g_colors.resultBg);
            SetTextColor(hdc, g_colors.textPrimary);
            return reinterpret_cast<INT_PTR>(g_resultBrush);
        }
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, (ctrl == g_hSubtitleLabel || ctrl == g_hFileLabel || ctrl == g_hStatusLabel) ? g_colors.textMuted : g_colors.textPrimary);
        return reinterpret_cast<INT_PTR>(g_panelBrush);
    }
    case WM_CTLCOLOREDIT:
    {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        HWND ctrl = reinterpret_cast<HWND>(lParam);
        if (ctrl == g_hResultBox)
        {
            SetBkColor(hdc, g_colors.resultBg);
            SetTextColor(hdc, g_colors.textPrimary);
            return reinterpret_cast<INT_PTR>(g_resultBrush);
        }
        SetBkColor(hdc, g_colors.inputBg);
        SetTextColor(hdc, g_colors.textPrimary);
        return reinterpret_cast<INT_PTR>(g_inputBrush);
    }
    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc{};
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_windowBrush);

        RECT header = { g_metrics.margin, g_metrics.margin, rc.right - g_metrics.margin, g_metrics.margin + g_metrics.headerHeight };
        DrawPanel(hdc, header);
        RECT top = { g_metrics.margin, header.bottom + g_metrics.panelGap, rc.right - g_metrics.margin, header.bottom + g_metrics.panelGap + 116 };
        DrawPanel(hdc, top);
        RECT actions = { g_metrics.margin, top.bottom + g_metrics.panelGap, rc.right - g_metrics.margin, top.bottom + g_metrics.panelGap + 60 };
        DrawPanel(hdc, actions);
        RECT results = { g_metrics.margin, actions.bottom + g_metrics.panelGap, rc.right - g_metrics.margin, rc.bottom - g_metrics.margin };
        DrawPanel(hdc, results);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_SELECT_FILE:
            if (!g_analysisRunning)
                OpenFilePicker(hwnd);
            return 0;
        case IDC_URL_INPUT:
            if (HIWORD(wParam) == EN_CHANGE && !g_analysisRunning)
            {
                char urlBuffer[2048] = {};
                GetWindowTextA(g_hUrlInput, urlBuffer, sizeof(urlBuffer));
                if (!TrimCopy(urlBuffer).empty() && !g_selectedFilePath.empty())
                    ResetSelectedFileUI();
            }
            return 0;
        case IDC_ANALYZE:
        {
            if (g_analysisRunning)
                return 0;
            char urlBuffer[2048] = {};
            GetWindowTextA(g_hUrlInput, urlBuffer, sizeof(urlBuffer));
            const std::string inputURL = TrimCopy(urlBuffer);
            g_lastReportText.clear();
            g_lastAnalystReportText.clear();
            g_lastIocReportText.clear();
            g_lastReportJson.clear();
            g_analystView = false;
            RefreshReportActionsState();
            SetWindowTextA(g_hResultBox, "BinaryLens Scan Result\r\n\r\nStatus: Starting a fresh analysis run...");
            // url mode runs inline because it is usually much shorter than file analysis.
            if (!inputURL.empty())
            {
                SetWindowTextA(g_hStatusLabel, "Running URL / IP analysis...");
                SetProgressVisible(false);
                const AnalysisReportData report = RunUrlAnalysisDetailed(inputURL);
                g_lastReportText = report.textReport;
                g_lastAnalystReportText = report.analystTextReport;
                g_lastIocReportText = report.iocTextReport;
                g_lastReportJson = report.jsonReport;
                RefreshDisplayedReport();
                SetWindowTextA(g_hStatusLabel, "URL / IP analysis complete.");
                ResetUrlUI();
                RefreshReportActionsState();
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }
            if (g_selectedFilePath.empty())
            {
                MessageBoxA(hwnd, "Paste a URL or IP, or select a file before starting analysis.", "BinaryLens", MB_OK | MB_ICONWARNING);
                return 0;
            }
            StartAnalysis(hwnd, g_selectedFilePath);
            return 0;
        }
        case IDC_EXPORT:
            if (!g_analysisRunning)
            {
                const int choice = MessageBoxA(hwnd,
                    "Click Yes to export JSON, or No to export TXT.",
                    "BinaryLens Export",
                    MB_YESNOCANCEL | MB_ICONQUESTION);
                if (choice == IDYES)
                    ExportLatestReport(hwnd, true);
                else if (choice == IDNO)
                    ExportLatestReport(hwnd, false);
            }
            return 0;
        case IDC_COPY:
            if (!g_analysisRunning)
            {
                const std::string active = GetActiveReportText();
                if (active.empty())
                {
                    MessageBoxA(hwnd, "Run an analysis first before copying a report.", "BinaryLens", MB_OK | MB_ICONINFORMATION);
                }
                else if (CopyTextToClipboard(hwnd, active))
                {
                    SetWindowTextA(g_hStatusLabel, "Report copied to clipboard.");
                }
                else
                {
                    MessageBoxA(hwnd, "Could not copy the report to the clipboard.", "BinaryLens", MB_OK | MB_ICONERROR);
                }
            }
            return 0;
        case IDC_VIEW_TOGGLE:
            if (!g_analysisRunning && !g_lastAnalystReportText.empty())
            {
                g_analystView = !g_analystView;
                RefreshDisplayedReport();
                RefreshReportActionsState();
                SetWindowTextA(g_hStatusLabel, g_analystView ? "Analyst view enabled." : "User view enabled.");
            }
            return 0;
        case IDC_EXPORT_IOC:
            if (!g_analysisRunning)
            {
                if (g_lastIocReportText.empty())
                    MessageBoxA(hwnd, "No IOC export is available for the last analysis.", "BinaryLens", MB_OK | MB_ICONINFORMATION);
                else
                {
                    const std::string path = GetSaveReportPath(hwnd, false);
                    if (!path.empty() && WriteTextFile(path, g_lastIocReportText))
                        SetWindowTextA(g_hStatusLabel, "IOC export saved.");
                }
            }
            return 0;
        case IDC_THEME_TOGGLE:
            if (!g_analysisRunning)
                ToggleTheme(hwnd);
            return 0;
        case IDC_CANCEL:
            if (g_analysisRunning)
            {
                RequestAnalysisCancellation();
                SetWindowTextA(g_hStatusLabel, "Cancellation requested...");
            }
            return 0;
        }
        break;

    // ui-thread message handlers own widget updates so background work stays decoupled from win32 state.
    case WM_APP_PROGRESS:
    {
        std::unique_ptr<UiTextPayload> payload(reinterpret_cast<UiTextPayload*>(lParam));
        if (payload)
        {
            SendMessageA(g_hProgressBar, PBM_SETPOS, payload->percent, 0);
            SetWindowTextA(g_hStatusLabel, payload->statusLine.c_str());
            if (payload->percent >= 100)
                SetProgressVisible(false);
            else
                SetProgressVisible(true);
        }
        return 0;
    }

    case WM_APP_RESULT:
    {
        std::unique_ptr<UiTextPayload> payload(reinterpret_cast<UiTextPayload*>(lParam));
        UpdateUiForRunningState(false);
        if (payload)
        {
            g_lastReportText = payload->text;
            g_lastAnalystReportText = payload->analystText;
            g_lastIocReportText = payload->iocText;
            g_lastReportJson = payload->jsonText;
            RefreshDisplayedReport();
            SetWindowTextA(g_hStatusLabel, payload->statusLine.c_str());
            RefreshReportActionsState();
        }
        SetProgressVisible(false);
        return 0;
    }

    case WM_DESTROY:
        DeleteThemeBrushes();
        DeleteAppFonts();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}
