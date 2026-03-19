#pragma once

// script-focused static abuse heuristics for interpreter, download, persistence, and evasion behavior.
#include <string>
#include <vector>

#include "scanners/file_scanner.h"

struct ScriptAbuseAnalysisResult
{
    bool analyzed = false;
    bool likelyScriptContent = false;
    bool hasDownloadCradle = false;
    bool hasEncodedPayload = false;
    bool hasExecutionAbuse = false;
    bool hasPersistenceAbuse = false;
    bool hasObfuscationTraits = false;
    unsigned int score = 0;
    std::vector<std::string> findings;
};

ScriptAbuseAnalysisResult AnalyzeScriptAbuseContent(const FileInfo& info);
