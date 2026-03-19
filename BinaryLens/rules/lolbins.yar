
rule LOLBins_Abuse_Generic
{
    meta:
        description = "Common LOLBins used for script or payload execution"
        score_boost = 12

    strings:
        $a = "mshta" nocase
        $b = "regsvr32" nocase
        $c = "rundll32" nocase
        $d = "wmic process call create" nocase
        $e = "powershell -enc" nocase
        $f = "bitsadmin" nocase

    condition:
        2 of them
}
