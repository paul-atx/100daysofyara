#100daysofyara

I've decided to play along but I don't have a twitter account. Github seems like a great place for a ruleset. Welcome to my 100 Days of Yara.

##Day 10
###IcedID
IcedID is used by cybercriminals to steal sensitive information. It is a multi-stage, modular, and polymorphic malware that is often used in targeted attacks. It is distributed through malicious emails, compromised websites, and malicious software downloads. Once installed, the malware uses a variety of techniques to steal credentials, banking information, and other sensitive data. It also has the ability to download additional malicious payloads and execute commands on the infected system. This makes it a particularly dangerous threat to businesses as it can spread quickly and steal valuable data.

I started by locating a few reported IcedId samples. The samples were packed, but after analyzing the strings against a corpus of known goodware, there was a pattern in the packed code that was consistent between samples and did not appear in my goodware collection. 

I wrote and tested a few rules throughout the day and merged them together into a single rule for day ten. You can get more matches by playing around with some of the wild card bytes, but you also start to pull in other families, like bazaar loader. Which is perhap not surprising given both Bazaar Loader and IcedID links to trickbot. Although rules written this way can't be expected to have a long shelf life, the rule was detecting on icedid samples collected throughout 2022 and even some this year. It's not perfect but its finding evil.



