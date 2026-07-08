# Vulnerability: Ensure Inactive Password Lock is Configured (Default Setting)
**Classification:** CIS
**Source:** Nuclei Template (`inactive-password-lock-default.yaml`)

## Description
This policy ensures the default user inactivity lock is configured properly.User accounts that remain inactive for more than 45 days after password expiration should be disabled.

## Secure Mitigation
Ensure the default INACTIVE parameter is set to 45 days for new accounts.To configure, run: sudo useradd -D -f 45

