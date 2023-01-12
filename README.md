# 100daysofyara

I've decided to play along but I don't have a twitter account. Github seems like a great place for a ruleset and a bit of a journal. Welcome to my 100 Days of YARA.

## Day 10 - IcedId
IcedID is used by cybercriminals to steal sensitive information. It is a multi-stage, modular, and polymorphic malware that is often used in targeted attacks. It is distributed through malicious emails, compromised websites, and malicious software downloads. Once installed, the malware uses a variety of techniques to steal credentials, banking information, and other sensitive data. It also has the ability to download additional malicious payloads and execute commands on the infected system. This makes it a particularly dangerous threat to businesses as it can spread quickly and steal valuable data.

I started by locating a few reported IcedId samples. The samples were packed, but there was a pattern in the packed code that was consistent between samples and did not appear in my goodware collection. 

I wrote and tested a few rules throughout the day and merged them together into a single rule for day ten. You can get more matches by playing around with some of the wild card bytes, but you also start to pull in other families, like bazaar loader. 

Although rules written this way can't be expected to have a long shelf life, the rule was detecting on IcedId samples collected throughout 2022 and even some this year. It's not perfect but its finding evil.

## Day 11 - Remcos RAT

Remcos RAT is a powerful Remote Administration Tool (RAT) used by malicious actors to gain access to remote systems. It is cross-platform, allowing attackers to gain access to Windows, macOS, and Linux systems. It has many features, including keylogging, remote command execution, file manipulation, and the ability to take screenshots. Remcos is a commercially available tool, but it is often used by malicious actors in targeted attacks. 

There are a few good rules out there working well for Remcos RAT, but some of them are a bit too specific to match on some Remcos samples, by generalizing these rules a bit you can get something that detects moore Remcos samples. The rule I made for day eleven had over 8k hits in my malware corpus, while other rules I evaluated only had 5k hits. This doesn't make the other rules less valuable. I like to make and run variations of rules to try identify and keep up with evolving malware families. Yara is a great way to identify these evolutions.

## Day 12 - Havoc C2

Havoc is a modern and malleable post-exploitation command and control framework. It's relatively new development and I haven't seen a lot of usage but its very capable. This will likely be used and tested by red teams. So lets make sure we have some detections for it. I compiled a few clients and made sure everything was working, then used the clients as a basis for rules.

There are a variety of methods for generating rules that i've experimented with. It's good to find a balance between spending a lot of time to make a high fidelity rule versus knocking something out quick and moving on to cover another threat. One tool that has helped me quickly create YARA rules 
