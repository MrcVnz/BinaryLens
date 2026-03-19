#pragma once

// pe import analysis contracts used to map api usage into behavioral capability clusters.
#include <string>
#include <vector>

struct ImportAnalysisResult
{
    bool fileOpened = false;
    bool isPE = false;
    bool importTableParsed = false;

    unsigned int totalImports = 0;
    unsigned int suspiciousImportCount = 0;

    std::vector<std::string> suspiciousImports;
    std::vector<std::string> allImportedFunctions;
    std::vector<std::string> notes;
    std::vector<std::string> capabilityClusters;
};

ImportAnalysisResult AnalyzePEImports(const std::string& filePath);
