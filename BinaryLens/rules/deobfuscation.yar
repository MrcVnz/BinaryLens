rule Encoded_Command_Stager
{
    strings:
        $a = "FromBase64String"
        $b = "-enc"
        $c = "Invoke-Expression"
        $d = "DownloadString"
    condition:
        2 of them
}
