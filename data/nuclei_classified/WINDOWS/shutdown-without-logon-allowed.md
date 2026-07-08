# Vulnerability: System Allows Shutdown Without Logging On
**Classification:** WINDOWS
**Source:** Nuclei Template (`shutdown-without-logon-allowed.yaml`)

## Description
Checks if the system allows shutdown without logging on, which could lead to denial-of-service attacks.

## Secure Mitigation
Restrict system shutdown to logged-in users to prevent unauthorized access.

