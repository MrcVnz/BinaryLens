rule Ransomware_Command_Pattern
{
    meta:
        description = "Recovery inhibition and log wiping commands"
        score_boost = 18

    strings:
        $vss = "vssadmin delete shadows" nocase
        $bcd = "bcdedit /set" nocase
        $wb = "wbadmin delete catalog" nocase
        $wevt = "wevtutil cl" nocase
        $cipher = "cipher /w:" nocase

    condition:
        2 of them
}

rule File_Encryption_Workflow_Generic
{
    meta:
        description = "Common file-encryption workflow references"
        score_boost = 16

    strings:
        $enc = "encrypt" nocase
        $rsa = "rsa" nocase
        $aes = "aes" nocase
        $ext = ".locked" nocase
        $note = "readme" nocase
        $recover = "recovery" nocase

    condition:
        ($enc and (1 of ($rsa,$aes)) and (1 of ($ext,$note))) or 4 of them
}
