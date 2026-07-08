# Vulnerability: SMB Shares - Enumeration
**Classification:** JS
**Source:** Nuclei Template (`smb-shares.yaml`)

## Description
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.

