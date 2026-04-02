#pragma once

// centralized app identity so the ui, update checker, and release dialog stay aligned.
namespace bl::app
{
#ifdef BINARYLENS_APP_VERSION
    inline constexpr const char* kVersion = BINARYLENS_APP_VERSION;
#else
    inline constexpr const char* kVersion = "1.1.0";
#endif

#ifdef BINARYLENS_UPDATE_OWNER
    inline constexpr const char* kUpdateOwner = BINARYLENS_UPDATE_OWNER;
#else
    inline constexpr const char* kUpdateOwner = "MrcVnz";
#endif

#ifdef BINARYLENS_UPDATE_REPO
    inline constexpr const char* kUpdateRepo = BINARYLENS_UPDATE_REPO;
#else
    inline constexpr const char* kUpdateRepo = "BinaryLens";
#endif
}
