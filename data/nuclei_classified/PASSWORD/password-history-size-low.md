# Vulnerability: Password History Size Too Low
**Classification:** PASSWORD
**Source:** Nuclei Template (`password-history-size-low.yaml`)

## Description
Checks if the password history count is too low or not configured, allowing password reuse.

## Secure Mitigation
Increase the password history count to at least 24 previous passwords to prevent rapid reuse of old passwords.

