# Vulnerability: Perforce Server - Passwordless User Accounts
**Classification:** CWE-306
**Source:** Nuclei Template (`perforce-passwordless-users.yaml`)

## Description
Perforce server contained user accounts with no password set, allowing unauthenticated access as those users. The user-users RPC was issued with the tag parameter to switch the server to tagged (client-FstatInfo) output, which omits the Password field entirely for passwordless accounts. Both ASCII and Unicode server modes were affected. SSL-enforcing servers are not affected.

