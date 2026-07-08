# Vulnerability: Perforce Server - Unauthenticated Remote Depot Access
**Classification:** CWE-306
**Source:** Nuclei Template (`perforce-remote-depot-unauth.yaml`)

## Description
Detected Perforce server allowed unauthenticated remote depot access via the hidden built-in "remote" user. This affected server versions below 2025.1 when the security level was below 4 (default is 0). The depot file listing and change list numbers were retrieved without authentication using the rmt-DbPipe RPC against the db.rev table.

