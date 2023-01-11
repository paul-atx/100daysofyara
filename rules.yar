import "pe"

rule Malware_IcedID
{
    meta:
        author = "paul"
        description = "Detects packed IcedId samples based on patterns in encrypted strings. Low false positives."
        days_of_yara = "10/100"
        hash = "8c25b5aac85cb8b66c2c30fc5ee465c1be8c81109d9fd1a72085470d1378a2d4"
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

rule Malware_Remcos
{
    meta:
        description = “Detects strings in Remcos RAT samples”
        hash = “698fe29ab7c4fb91466faee9d241f2d058eb19a97bf5df5c07daef68dc344bae”
    strings:
        $ = “[Cleared browsers logins and cookies.]”
        $ = “[Chrome StoredLogins found, cleared!]”
        $ = “[Firefox cookies found, cleared!]”
        $ = “[Firefox StoredLogins Cleared!]”
        $ = “[Chrome Cookies found, cleared!]”
        $ = “[Firefox StoredLogins not found]”
        $ = “[Chrome StoredLogins not found]”
        $ = “[Text pasted from clipboard]”
        $ = “[Firefox Cookies not found]”
        $ = “[Text copied to clipboard]”
        $ = “[Chrome Cookies not found]”
    condition:
        pe.is_pe and 7 of them
}

