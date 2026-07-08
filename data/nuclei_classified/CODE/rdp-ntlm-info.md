# Vulnerability: RDP - NTLM Information Disclosure
**Classification:** CODE
**Source:** Nuclei Template (`rdp-ntlm-info.yaml`)

## Description
The enumeration gathered NTLM-related information from remote RDP services with Network Level Authentication (NLA) enabled. By sending an incomplete authentication request, it disclosed details such as the target’s NetBIOS and DNS names, domain, product version, and system time, which proved useful for network reconnaissance and asset profiling.

