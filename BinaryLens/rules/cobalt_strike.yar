rule cobalt_strike_style_indicators
{
    meta:
        description = "flags beacon-style named pipe and common cobalt strike strings"
        score_boost = 9
    strings:
        $a = "\\\\.\\pipe\\msagent_" nocase
        $b = "\\\\.\\pipe\\postex_" nocase
        $c = "beacon" nocase
        $d = "sleep_mask" nocase
    condition:
        2 of them
}
