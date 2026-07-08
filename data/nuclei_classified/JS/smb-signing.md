# Vulnerability: SMB Signing Not Required
**Classification:** JS
**Source:** Nuclei Template (`smb-signing.yaml`)

## Description
Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.

