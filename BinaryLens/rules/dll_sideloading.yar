rule dll_sideloading_loader_context
{
    meta:
        description = "flags common sideloading and loader adjacency patterns"
        score_boost = 8
    strings:
        $a = "LoadLibraryW" nocase
        $b = ".dll" nocase
        $c = "SetDllDirectory" nocase
    condition:
        2 of them
}
