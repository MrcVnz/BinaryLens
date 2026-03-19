#pragma once

// windows signature validation interfaces for publisher and trust context checks.
#include <string>

struct SignatureCheckResult
{
    bool fileChecked = false;
    bool isSigned = false;
    bool signatureValid = false;
    bool hasPublisher = false;

    std::string publisher;
    std::string summary;
};

bool ShouldCheckSignature(const std::string& extension);
SignatureCheckResult CheckFileSignature(const std::string& filePath);
