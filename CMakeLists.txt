cmake_minimum_required(VERSION 3.21)
project(BinaryLensQt LANGUAGES CXX)

set(BINARYLENS_APP_VERSION "1.1.0")

set(CMAKE_SUPPRESS_REGENERATION ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC OFF)

if (DEFINED ENV{QT_ROOT} AND NOT DEFINED CMAKE_PREFIX_PATH)
    list(APPEND CMAKE_PREFIX_PATH "$ENV{QT_ROOT}")
endif()

if (NOT DEFINED WINDEPLOYQT_PATH AND DEFINED ENV{WINDEPLOYQT_PATH})
    set(WINDEPLOYQT_PATH "$ENV{WINDEPLOYQT_PATH}")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

set(BINARYLENS_CORE_SOURCES
    BinaryLens/src/analyzers/archive_analyzer.cpp
    BinaryLens/src/analyzers/import_analyzer.cpp
    BinaryLens/src/analyzers/indicator_extractor.cpp
    BinaryLens/src/analyzers/pe_analyzer.cpp
    BinaryLens/src/analyzers/url_analyzer.cpp
    BinaryLens/src/analyzers/embedded_payload_analyzer.cpp
    BinaryLens/src/analyzers/script_abuse_analyzer.cpp
    BinaryLens/src/core/analysis_control.cpp
    BinaryLens/src/core/analysis_cache.cpp
    BinaryLens/src/core/analysis_engine.cpp
    BinaryLens/src/core/behavior_simulator.cpp
    BinaryLens/src/core/confidence_engine.cpp
    BinaryLens/src/core/deobfuscation_engine.cpp
    BinaryLens/src/core/evasion_engine.cpp
    BinaryLens/src/core/evidence_calibrator.cpp
    BinaryLens/src/core/ioc_intelligence.cpp
    BinaryLens/src/core/low_level_semantics.cpp
    BinaryLens/src/core/memory_scanner.cpp
    BinaryLens/src/core/mitre_mapper.cpp
    BinaryLens/src/core/ml_classifier.cpp
    BinaryLens/src/core/plugin_engine.cpp
    BinaryLens/src/core/risk_engine.cpp
    BinaryLens/src/core/verdict_engine.cpp
    BinaryLens/src/core/yara_engine.cpp
    BinaryLens/src/scanners/file_scanner.cpp
    BinaryLens/src/scanners/url_scanner.cpp
    BinaryLens/src/services/api_client.cpp
    BinaryLens/src/services/signature_checker.cpp
    BinaryLens/src/asm/asm_bridge.cpp
)

set(BINARYLENS_ASM_SOURCES
    BinaryLens/asm/pattern_scan_x64.asm
    BinaryLens/asm/entrypoint_profile_x64.asm
    BinaryLens/asm/cpu_runtime_x64.asm
    BinaryLens/asm/byte_profile_x64.asm
    BinaryLens/asm/token_prefilter_x64.asm
    BinaryLens/asm/code_surface_x64.asm
    BinaryLens/asm/opcode_family_x64.asm
)

if (MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_language(ASM_MASM)
    list(APPEND BINARYLENS_CORE_SOURCES ${BINARYLENS_ASM_SOURCES})
endif()

set(BINARYLENS_QT_SOURCES
    qt_app/src/main.cpp
    qt_app/src/main_window.cpp
    qt_app/src/analysis_worker.cpp
    qt_app/src/update_checker.cpp
    qt_app/src/update_dialog.cpp
)

set(BINARYLENS_QT_HEADERS
    qt_app/include/main_window.h
    qt_app/include/analysis_worker.h
    qt_app/include/app_version.h
    qt_app/include/update_checker.h
    qt_app/include/update_dialog.h
)

set(BINARYLENS_QT_RESOURCES
    qt_app/resources/binarylens_resources.qrc
    qt_app/resources/binarylens.rc
)

add_executable(BinaryLensQt WIN32
    ${BINARYLENS_CORE_SOURCES}
    ${BINARYLENS_QT_SOURCES}
    ${BINARYLENS_QT_HEADERS}
    ${BINARYLENS_QT_RESOURCES}
)

target_include_directories(BinaryLensQt PRIVATE
    BinaryLens/include
    qt_app/include
)

target_link_libraries(BinaryLensQt PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    Comctl32
    Crypt32
    Wintrust
    Version
    Ws2_32
    Winhttp
    Psapi
    Mpr
    Userenv
)

target_compile_definitions(BinaryLensQt PRIVATE
    NOMINMAX
    UNICODE
    _UNICODE
    BINARYLENS_APP_VERSION="${BINARYLENS_APP_VERSION}"
    BINARYLENS_UPDATE_OWNER="MrcVnz"
    BINARYLENS_UPDATE_REPO="BinaryLens"
)

if (MSVC)
    target_compile_options(BinaryLensQt PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/W3>
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
    )
endif()

if (WIN32)
    if (NOT WINDEPLOYQT_PATH AND CMAKE_PREFIX_PATH)
        list(GET CMAKE_PREFIX_PATH 0 _qt_prefix)
        set(WINDEPLOYQT_PATH "${_qt_prefix}/bin/windeployqt.exe")
    endif()

    # avoid passing an empty quoted argument to windeployqt
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(_windeployqt_mode --debug)
    else()
        set(_windeployqt_mode --release)
    endif()

    set(_binarylens_post_build_commands
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:BinaryLensQt>/config"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_SOURCE_DIR}/BinaryLens/config/config.json"
                "$<TARGET_FILE_DIR:BinaryLensQt>/config/config.json"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_SOURCE_DIR}/BinaryLens/config/config.example.json"
                "$<TARGET_FILE_DIR:BinaryLensQt>/config/config.example.json"
    )

    if (WINDEPLOYQT_PATH)
        add_custom_command(TARGET BinaryLensQt POST_BUILD
            COMMAND "${WINDEPLOYQT_PATH}" ${_windeployqt_mode} "$<TARGET_FILE:BinaryLensQt>"
            ${_binarylens_post_build_commands}
            COMMENT "Deploying Qt runtime for BinaryLensQt and staging config files..."
            VERBATIM
        )
    else()
        message(WARNING "WINDEPLOYQT_PATH is not set; Qt runtime deployment will be skipped for this configure.")
        add_custom_command(TARGET BinaryLensQt POST_BUILD
            ${_binarylens_post_build_commands}
            COMMENT "Staging BinaryLensQt config files without Qt runtime deployment..."
            VERBATIM
        )
    endif()
endif()
