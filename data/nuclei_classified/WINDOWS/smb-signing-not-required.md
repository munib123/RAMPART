# Vulnerability: SMB Signing Not Required
**Classification:** WINDOWS
**Source:** Nuclei Template (`smb-signing-not-required.yaml`)

## Description
Checks if SMB signing is not required, exposing SMB communications to man-in-the-middle attacks.

## Secure Mitigation
Configure SMB to require security signatures for communication.

