#pragma once

// focused file-type resolution helpers used to merge header evidence, textual hints, and extension context.
#include <string>
#include <vector>

namespace bl::filetype
{
    struct FileTypeDetection
    {
        std::string displayedType;
        std::string realType;
        std::string familyTag;
        bool peLike = false;
        bool scriptLike = false;
        bool archiveInspectionCandidate = false;
        bool typeMismatchLikely = false;
    };

    FileTypeDetection DetectFileType(const std::string& fileName,
                                     const std::string& extension,
                                     const std::vector<unsigned char>& header,
                                     const std::string& printablePreview = "");

    std::string DetectRealFileType(const std::vector<unsigned char>& header,
                                   const std::string& extension = "",
                                   const std::string& printablePreview = "");
}
