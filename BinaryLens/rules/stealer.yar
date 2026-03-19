rule Credential_Stealer_Generic
{
    meta:
        description = "Generic browser credential or token stealing references"
        score_boost = 16

    strings:
        $login = "login data" nocase
        $cookies = "cookies.sqlite" nocase
        $dpapi = "cryptunprotectdata" nocase
        $vault = "vaultcmd" nocase
        $lsass = "lsass" nocase
        $token = "token" nocase
        $sqlite = "sqlite" nocase

    condition:
        ($dpapi and (1 of ($login,$cookies,$vault))) or 3 of them
}

rule Keylogger_Generic
{
    meta:
        description = "Keylogging or surveillance style API references"
        score_boost = 12

    strings:
        $gaks = "getasynckeystate" nocase
        $gks = "getkeystate" nocase
        $hook = "setwindowshookex" nocase
        $ll = "wh_keyboard_ll" nocase
        $clip = "clipboard" nocase

    condition:
        2 of them
}
