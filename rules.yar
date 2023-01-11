import "pe"

rule Malware_IcedID
{
    meta:
        author = "paul-atx"
        description = "Detects packed IcedId samples based on patterns in encrypted strings. Low false positives."
        days_of_yara = 10/100
    strings:
        $h2 = { 48 63 44 24 ?0 48 63 4c 24 ?4 66 3b }
        $h4 = { 48 63 44 24 ?? 48 63 4c 24 24 3a }
        $h5 = { 44 24 58 48 63 44 24 4c 3a }
        $h6 = { 44 24 ?? 48 63 4? 24 4? 3a }
        $h8 = { 44 24 50 48 63 40 3c 3a }
        $h9 = { 44 24 ?0 48 63 40 3c 3a }
        $h10 = { 44 24 20 48 63 44 24 30 66 3b }
    condition:
        pe.is_pe and (filesize > 50KB and filesize < 2MB) and 2 of them
}
