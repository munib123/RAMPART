# Vulnerability: Fortinet Remote Authentication Timeout Not Set - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`remote-auth-timeout.yaml`)

## Description
Fortinet remote authentication timeout functionality is recommended to be enabled. Lack of a set timeout can allow an attacker to act within that threshold if the administrator is away from the computer, thereby making it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.

