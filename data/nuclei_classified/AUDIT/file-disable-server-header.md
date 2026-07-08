# Vulnerability: Disable Apache2 Server Header
**Classification:** AUDIT
**Source:** Nuclei Template (`file-disable-server-header.yaml`)

## Description
Ensures that 'ServerTokens Prod' and 'ServerSignature Off' are correctly set in Apache to prevent server information leakage.

## Secure Mitigation
Set 'ServerTokens Prod' and 'ServerSignature Off' in Apache configuration and restart the service.

