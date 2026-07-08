# Vulnerability: Enforce Apache2 ServerTokens Prod
**Classification:** AUDIT
**Source:** Nuclei Template (`file-enforce-server-tokens-prod.yaml`)

## Description
ServerTokens should be set to 'Prod' to prevent Apache from exposing version details in response headers.

## Secure Mitigation
Set 'ServerTokens Prod' in the Apache configuration file and restart the service.

