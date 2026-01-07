rule Simple_Malware_Detection
{
    meta:
        description = "Simple YARA rule example for malware detection"
        author = "Security Researcher"
        date = "2026-01-07"
        reference = "training-example"

    strings:
        $mz = "MZ"
        $suspicious_string = "CreateRemoteThread" nocase

    condition:
        $mz at 0 and $suspicious_string
}
