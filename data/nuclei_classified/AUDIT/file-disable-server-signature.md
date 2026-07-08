# Vulnerability: Disable Apache Server Signature
**Classification:** AUDIT
**Source:** Nuclei Template (`file-disable-server-signature.yaml`)

## Description
Disabling the server signature prevents Apache from revealing version details in error pages.

## Secure Mitigation
Set 'ServerSignature Off' in the Apache configuration file and restart the service.

