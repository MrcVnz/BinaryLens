rule Suspicious_PowerShell_Loader
{
    meta:
        description = "Generic PowerShell downloader / stager behavior"
        score_boost = 14

    strings:
        $ps = "powershell" nocase
        $enc = "-enc" nocase
        $iex = "invoke-expression" nocase
        $iwr = "invoke-webrequest" nocase
        $dls = "downloadstring" nocase
        $wc = "system.net.webclient" nocase
        $b64 = "frombase64string" nocase

    condition:
        ($ps and ($enc or $iex or $b64) and (1 of ($iwr,$dls,$wc))) or 4 of them
}

rule Suspicious_Script_Dropper_Generic
{
    meta:
        description = "Script-based dropper staging pattern"
        score_boost = 12

    strings:
        $cmd = "cmd.exe" nocase
        $ps1 = ".ps1" nocase
        $temp = "%temp%" nocase
        $appdata = "%appdata%" nocase
        $start = "start-process" nocase
        $exec = "wscript" nocase
        $expand = "expand-archive" nocase

    condition:
        3 of them
}


rule Suspicious_LNK_Or_Lure_Dropper
{
    meta:
        description = "Shortcut or lure naming combined with execution helper strings"
        score_boost = 14

    strings:
        $a = ".lnk" nocase
        $b = "invoice" nocase
        $c = "payment" nocase
        $d = "mshta" nocase
        $e = "cmd.exe /c" nocase
        $f = "powershell" nocase

    condition:
        ($a and 1 of ($d,$e,$f)) or (($b or $c) and 2 of them)
}
