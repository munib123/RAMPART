# Vulnerability: Null Session Allowed
**Classification:** WINDOWS
**Source:** Nuclei Template (`null-session-allowed.yaml`)

## Description
Checks if null sessions are allowed via any entry in the NullSessionPipes registry key, posing a security risk.

## Secure Mitigation
Disable null sessions by ensuring no entries are allowed in the NullSessionPipes registry key.

