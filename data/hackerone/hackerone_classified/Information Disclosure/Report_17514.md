# HackerOne Report: Information Disclosure (phpinfo())
**Report ID:** 17514
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
URL :- https://staging.uzbey.com/phpinfo.php

Description :-
phpinfo() is a debug functionality that prints out detailed information on both the system and the PHP configuration.

An attacker can obtain information such as: 
•Exact PHP version.
•Exact OS and its version.
•Details of the PHP configuration.
•Internal IP addresses.
•Server environment variables.
•Loaded PHP extensions and their configurations.
This information can help an attacker gain more information on the system. After gaining detailed information, the attacker can research known vulnerabilities for that system under review. The attacker can also use this information during the exploitation of other vulnerabilities. 

## Discussion & Remediation Timeline
