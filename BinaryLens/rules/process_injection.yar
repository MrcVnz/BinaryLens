rule Injection_API_Chain
{
    strings:
        $a = "WriteProcessMemory"
        $b = "CreateRemoteThread"
        $c = "VirtualAllocEx"
        $d = "NtCreateThreadEx"
    condition:
        2 of them
}
