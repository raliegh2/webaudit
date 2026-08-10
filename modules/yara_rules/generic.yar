/*
  generic.yar — small bundled generic detection rules for localhunt.
  These are broad heuristic rules intended as a starting point, not a
  replacement for a maintained threat-intel feed. Supply --yara-rules
  with a custom directory for stronger coverage.
*/

rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "Detects PowerShell EncodedCommand usage, common in fileless malware"
        severity = "medium"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "FromBase64String" nocase
    condition:
        any of them
}

rule Suspicious_Double_Extension
{
    meta:
        description = "Filename with a double extension often used to disguise executables"
        severity = "low"
    strings:
        $a = ".pdf.exe" nocase
        $b = ".doc.exe" nocase
        $c = ".jpg.exe" nocase
        $d = ".txt.exe" nocase
    condition:
        any of them
}

rule Generic_Reverse_Shell_Strings
{
    meta:
        description = "Common strings seen in reverse shell payloads"
        severity = "high"
    strings:
        $a = "/bin/sh -i" nocase
        $b = "socket.connect" nocase
        $c = "nc -e /bin/sh" nocase
        $d = "bash -i >& /dev/tcp" nocase
    condition:
        any of them
}
