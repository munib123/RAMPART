# Nuclei Template: OpenText Filr - Guest Access Enabled
**Template ID:** opentext-filr-guest-access
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Medium
**CWE:** CWE-284
**Source:** Nuclei Template (`opentext-filr-guest-access.yaml`)

## Vulnerability Information & PoC

## Description
OpenText Filr (formerly Micro Focus/Novell Filr) had guest access enabled, allowing unauthenticated users to access the system as a Guest, exposing GuestUser: 'true' and an "Enter as Guest" option on the SSF login page.

## Impact
Anonymous users can access publicly shared files and folders without authentication, potentially exposing sensitive internal documents.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ssf/a/do?p_name=ss_forum&p_action=1&action=__login
```

## Remediation
Disable guest access via Admin Console (Port 8443) > System > Web Application > uncheck "Allow Guest access".
Ensure Filr instances exposed to the internet do not have guest access enabled.

## References
- https://www.microfocus.com/documentation/filr/filr-23.2/filr-admin/access.html
- https://www.microfocus.com/documentation/filr/filr-23.2/filr-inst/bjm9tb7.html
- https://opentext.com/products/filr
