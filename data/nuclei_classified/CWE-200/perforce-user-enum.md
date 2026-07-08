# Vulnerability: Perforce Server - User Enumeration
**Classification:** CWE-200
**Source:** Nuclei Template (`perforce-user-enum.yaml`)

## Description
Detected Perforce server allowed anonymous user listing due to run.users.authorize being set to 0 (the default). The server returned a full list of users including usernames, email addresses, and full names without authentication. Both ASCII and Unicode server modes were affected. SSL-enforcing servers are not affected.

