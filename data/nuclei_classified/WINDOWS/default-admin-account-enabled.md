# Vulnerability: Default Administrator Account Enabled
**Classification:** WINDOWS
**Source:** Nuclei Template (`default-admin-account-enabled.yaml`)

## Description
Detected built-in Administrator account was enabled, which is a common target for brute-force and credential stuffing attacks.

## Secure Mitigation
Disable the built-in Administrator account and use a separate named admin account for administrative tasks. Run: net user Administrator /active:no

