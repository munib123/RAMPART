# Vulnerability: IcedID Infrastructure - Detect
**Classification:** C2
**Source:** Nuclei Template (`icedid.yaml`)

## Description
IcedID, also known as BokBot, is a modular banking trojan that targets user financial information and is capable of acting as a dropper for other malware. It uses a man-in-the-browser attack to steal financial information, including login credentials for online banking sessions. Once it successfully completes its initial attack, it uses the stolen information to take over banking accounts and automate fraudulent transactions. IcedID is primarily dropped as a secondary payload from other malware, most notably Emotet, in addition to its own malspam campaigns. IcedID uses multiple injection methods to evade antivirus and other malware detection methods, such as injecting itself into operating system (OS) memory and regular processes. The malware authors are known to update IcedID to increase persistence and evade new detection efforts.

