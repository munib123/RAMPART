# Vulnerability: Public DNS Resolving to Private IP Addresses
**Classification:** CWE-200
**Source:** Nuclei Template (`dns-internal-ip-disclosure.yaml`)

## Description
Detected when a public domain's DNS A records resolved to private or reserved IP addresses, potentially revealing internal network topology to external parties.

