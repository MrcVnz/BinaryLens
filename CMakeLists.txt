cmake_minimum_required(VERSION 3.21)
project(BinaryLensQt LANGUAGES CXX ASM_MASM)

set(CMAKE_SUPPRESS_REGENERATION ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC OFF)

set(CMAKE_PREFIX_PATH "C:/Qt/6.10.2/msvc2022_64")
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
    BinaryLens/src/core/analysis_engine.cpp
    BinaryLens/src/core/behavior_simulator.cpp
    BinaryLens/src/core/confidence_engine.cpp
    BinaryLens/src/core/deobfuscation_engine.cpp
    BinaryLens/src/core/evasion_engine.cpp
    BinaryLens/src/core/ioc_intelligence.cpp
    BinaryLens/src/core/memory_scanner.cpp
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
    BinaryLens/asm/pattern_scan_x64.asm
    BinaryLens/asm/entrypoint_profile_x64.asm
)

set(BINARYLENS_QT_SOURCES
    qt_app/src/main.cpp
    qt_app/src/main_window.cpp
    qt_app/src/analysis_worker.cpp
)

set(BINARYLENS_QT_HEADERS
    qt_app/include/main_window.h
    qt_app/include/analysis_worker.h
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
    BinaryLens/third_party
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
)

if (MSVC)
    target_compile_options(BinaryLensQt PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/W3>
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
    )
endif()

if (WIN32)
    add_custom_command(TARGET BinaryLensQt POST_BUILD
        COMMAND "C:/Qt/6.10.2/msvc2022_64/bin/windeployqt.exe"
                --debug
                "$<TARGET_FILE:BinaryLensQt>"
        COMMENT "Deploying Qt runtime for BinaryLensQt..."
    )
endif()