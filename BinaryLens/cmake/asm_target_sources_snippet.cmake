# keep the entrypoint profiler in its own masm unit and compile both asm files.
# this variant matches the layout shown in the user's build log, where the top-level
# cmake project sits one directory above the BinaryLens source folder.
if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_language(ASM_MASM)

    target_sources(BinaryLensQt PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/BinaryLens/asm/pattern_scan_x64.asm
        ${CMAKE_CURRENT_SOURCE_DIR}/BinaryLens/asm/entrypoint_profile_x64.asm
    )

    set_source_files_properties(
        ${CMAKE_CURRENT_SOURCE_DIR}/BinaryLens/asm/pattern_scan_x64.asm
        ${CMAKE_CURRENT_SOURCE_DIR}/BinaryLens/asm/entrypoint_profile_x64.asm
        PROPERTIES LANGUAGE ASM_MASM
    )
endif()
