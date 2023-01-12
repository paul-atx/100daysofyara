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

rule Malware_Remcos_RAT
{
    meta:
        author = "paul"
        description = “Detects strings in Remcos RAT samples”
        days_of_yara = "11/100"
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

rule C2_Havoc_Client {
    meta:
        author = “paul”
        description = “Code-based YARA rule composed from potentially unique basic blocks for the selected set of samples/family.”
        days_of_yara = "12/100"
    strings:
        $blockhash_0x104db5f95e06aed9 = { 4883ec28 4989c9 e8???????? 488d0c01 e8???????? 4c89c8 4883c428 c3 }
        $blockhash_0x350a6a55339c76f4 = { 4c8b442478 488b13 41b904000000 31c9 e8???????? 4889c6 4885c0 75?? }
        $blockhash_0x4fe57f71bbdd93b3 = { 488b4108 83ea04 448b00 4883c004 83791c00 895114 48894108 4489c0 0fc8 410f44c0 }
        $blockhash_0x8397c8b8ffc1fc86 = { 56 53 89cb 4883ec28 65488b042560000000 488b4018 488b7020 4989f3 }
        $blockhash_0x8bb9a3b81a011522 = { 31c0 4183781000 0f95c0 01c0 89442458 498b4008 4889442460 }
        $blockhash_0xc2a78122f17b1a46 = { 48897b22 488b13 4989d9 4989f0 b902000000 e8???????? 85c0 74?? }
        $blockhash_0xd1b0a2b6260ed040 = { 4881c418010000 b801000000 5b 5e 5f 5d 415c 415d 415e 415f c3 }
        $blockhash_0xd2453c6d288d303f = { 488b0b 4989f1 4c8d05???????? 488d15???????? 488b01 ff5048 85c0 75?? }
        $blockhash_0xe6929ad76ed0b6b0 = { 4d8b402a 41b904000000 31c9 e8???????? 4889c7 4885c0 74?? }
        $blockhash_0xf02eb28d96e69775 = { 83e804 4429c0 894114 4489c0 4c01c8 48894108 4885d2 74?? }
    condition:
        7 of them
}
