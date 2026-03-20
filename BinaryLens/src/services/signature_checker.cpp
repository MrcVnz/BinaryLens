#include "services/signature_checker.h"

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <algorithm>
// authenticode inspection for signer identity, validity, and trust context.

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// keep utf conversions local so the trust code stays platform-focused.
static std::wstring ToWide(const std::string& input)
{
    if (input.empty())
        return L"";

    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
    if (sizeNeeded <= 0)
        return L"";

    std::wstring result(sizeNeeded - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &result[0], sizeNeeded);
    return result;
}

static std::string ToUTF8(const std::wstring& input)
{
    if (input.empty())
        return "";

    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0)
        return "";

    std::string result(sizeNeeded - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &result[0], sizeNeeded, nullptr, nullptr);
    return result;
}

static std::string ToLowerCopy(const std::string& s)
{
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// limits authenticode work to file types where publisher trust is meaningful.
bool ShouldCheckSignature(const std::string& extension)
{
    const std::string ext = ToLowerCopy(extension);
    return ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".ocx" || ext == ".scr" || ext == ".msi";
}

// publisher text is best-effort enrichment and should not block signature verdicts.
static std::string ExtractPublisherNameFromCertificate(PCCERT_CONTEXT certContext)
{
    if (!certContext)
        return "";

    DWORD needed = CertGetNameStringW(
        certContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        nullptr,
        nullptr,
        0
    );

    if (needed <= 1)
        return "";

    std::wstring name(needed - 1, L'\0');

    CertGetNameStringW(
        certContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        nullptr,
        &name[0],
        needed
    );

    return ToUTF8(name);
}

// queries the windows trust stack and extracts signer details for downstream context.
SignatureCheckResult CheckFileSignature(const std::string& filePath)
{
    SignatureCheckResult result;
    result.fileChecked = true;

    const std::wstring widePath = ToWide(filePath);

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = widePath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // ask the windows trust stack first, then enrich the result with publisher text.
    LONG trustStatus = WinVerifyTrust(
        nullptr,
        &policyGUID,
        &trustData
    );

    if (trustStatus == ERROR_SUCCESS)
    {
        result.isSigned = true;
        result.signatureValid = true;
        result.summary = "Valid Authenticode signature";
    }
    else if (trustStatus == TRUST_E_NOSIGNATURE ||
        trustStatus == TRUST_E_SUBJECT_FORM_UNKNOWN ||
        trustStatus == TRUST_E_PROVIDER_UNKNOWN)
    {
        result.isSigned = false;
        result.signatureValid = false;
        result.summary = "File is not digitally signed";
    }
    else
    {
        result.isSigned = true;
        result.signatureValid = false;
        result.summary = "Digital signature present but validation failed";
    }

    HCERTSTORE certStore = nullptr;
    HCRYPTMSG cryptMsg = nullptr;
    PCCERT_CONTEXT certContext = nullptr;

    BOOL queryOk = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        widePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        nullptr,
        nullptr,
        nullptr,
        &certStore,
        &cryptMsg,
        nullptr
    );

    if (queryOk && certStore)
    {
        certContext = CertEnumCertificatesInStore(certStore, nullptr);
        if (certContext)
        {
            result.publisher = ExtractPublisherNameFromCertificate(certContext);
            if (!result.publisher.empty())
                result.hasPublisher = true;
        }
    }

    if (certContext)
        CertFreeCertificateContext(certContext);

    if (certStore)
        CertCloseStore(certStore, 0);

    if (cryptMsg)
        CryptMsgClose(cryptMsg);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGUID, &trustData);

    return result;
}
