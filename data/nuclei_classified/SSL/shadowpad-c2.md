# Vulnerability: ShadowPad C2 Infrastructure - Detect
**Classification:** SSL
**Source:** Nuclei Template (`shadowpad-c2.yaml`)

## Description
ShadowPad constitutes various plugins having specific functionality and the malware has the capability to “plug” or “unplug” these plugins at run-time in shellcode format. It can also load additional plugins dynamically from the C2 server when required.

