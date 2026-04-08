#include "analyzers/script_abuse_analyzer.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace
{
    // this analyzer is intentionally text-first because many abusive scripts are renamed before delivery.
    std::string ToLowerCopy(std::string value)
    // normalizes text here so later comparisons stay simple and predictable.
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    // findings and score are updated together so new rules do not forget one side of the output.
    void AddFinding(ScriptAbuseAnalysisResult& result, const std::string& finding, unsigned int scoreBoost)
    // adds this detail through one gate so duplicate or noisy output stays under control.
    {
        if (std::find(result.findings.begin(), result.findings.end(), finding) == result.findings.end())
            result.findings.push_back(finding);
        result.score += scoreBoost;
    }

    // token buckets keep the checks readable while covering multiple script families.
    bool ContainsAny(const std::string& text, const std::vector<std::string>& tokens)
    // answers this contains any check in one place so the surrounding logic stays readable.
    {
        for (const auto& token : tokens)
        {
            if (text.find(token) != std::string::npos)
                return true;
        }
        return false;
    }
}

// script abuse analysis stays content-driven so renamed payloads still leave useful traces.
ScriptAbuseAnalysisResult AnalyzeScriptAbuseContent(const FileInfo& info)
// runs the analyze script abuse content pass and returns a focused result for the broader script abuse analysis pipeline.
{
    ScriptAbuseAnalysisResult result;

    // merge cached text with extracted indicators so renamed scripts still leave useful traces.
    // combine sampled text and extracted indicators because either source can hold the better clue set.
    std::string text = info.cachedPrintableText;
    for (const auto& item : info.extractedIndicators)
        text += "\n" + item;
    if (text.empty())
        return result;

    result.analyzed = true;
    const std::string lower = ToLowerCopy(text);

    // uses content-first script detection so renamed payloads can still be classified correctly.
    const bool contentLooksScript = info.isScriptLike ||
        ContainsAny(lower, {
            "powershell", "cmd.exe", "wscript", "cscript", "mshta", "javascript", "vbscript", "function ",
            "set-object", "new-object", "invoke-webrequest", "wget ", "curl ", "start-process", "reg add"
        });
    result.likelyScriptContent = contentLooksScript;

    // leave early once the sample stops looking script-driven, since later checks assume script context.
    if (!contentLooksScript)
        return result;

    // download cradles are a strong early-stage execution signal.
    if (ContainsAny(lower, {"invoke-webrequest", "downloadstring", "downloadfile", "urldownloadtofile", "bitsadmin", "certutil -urlcache", "mshta http", "frombase64string"}))
    {
        result.hasDownloadCradle = true;
        AddFinding(result, "download cradle or remote payload retrieval logic detected", 14);
    }

    if (ContainsAny(lower, {"-enc ", "-encodedcommand", "frombase64string", "base64_decode", "atob(", "chr(", "charcodeat", "concat(", "replace(", "xor"}))
    {
        result.hasEncodedPayload = true;
        AddFinding(result, "encoded, transformed, or layered script payload traits detected", 12);
    }

    // execution abuse stays separate from download and persistence so the report can explain which lane fired.
    if (ContainsAny(lower, {"start-process", "powershell -", "cmd /c", "cmd.exe /c", "rundll32", "regsvr32", "wscript.shell", "shell.application", "createobject", "winmgmts:"}))
    {
        result.hasExecutionAbuse = true;
        AddFinding(result, "interpreter or lolbin execution abuse traits detected", 12);
    }

    if (ContainsAny(lower, {"currentversion\\run", "startup", "schtasks", "scheduledtasks", "register-scheduledtask", "hkcu\\software\\microsoft\\windows\\currentversion\\run", "hklm\\software\\microsoft\\windows\\currentversion\\run"}))
    {
        result.hasPersistenceAbuse = true;
        AddFinding(result, "script-driven persistence behavior detected", 10);
    }

    // keep stealth terms separate so they do not get diluted by execution-only hints.
    if (ContainsAny(lower, {"-windowstyle hidden", "hidden", "isdebuggerpresent", "sleep", "start-sleep", "amsi", "amsiutils", "set-mppreference", "add-mppreference"}))
    {
        result.hasObfuscationTraits = true;
        AddFinding(result, "script evasion, stealth, or anti-analysis traits detected", 10);
    }

    return result;
}
