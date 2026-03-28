rule dotnet_reflection_loader
{
    meta:
        description = "flags .net reflection and in-memory assembly execution patterns"
        score_boost = 7
    strings:
        $a = "Assembly.Load" nocase
        $b = "GetMethod" nocase
        $c = "Invoke" nocase
        $d = "System.Reflection" nocase
    condition:
        2 of them
}
