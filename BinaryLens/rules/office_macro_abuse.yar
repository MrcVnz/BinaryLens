rule office_macro_abuse
{
    meta:
        description = "flags office macro execution and shell launching patterns"
        score_boost = 8
    strings:
        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "WScript.Shell" nocase
        $d = "Shell(" nocase
    condition:
        2 of them
}
