# Vulnerability: OpenText Filr - Guest Access Enabled
**Classification:** CWE-284
**Source:** Nuclei Template (`opentext-filr-guest-access.yaml`)

## Description
OpenText Filr (formerly Micro Focus/Novell Filr) had guest access enabled, allowing unauthenticated users to access the system as a Guest, exposing GuestUser: 'true' and an "Enter as Guest" option on the SSF login page.

## Secure Mitigation
Disable guest access via Admin Console (Port 8443) > System > Web Application > uncheck "Allow Guest access".
Ensure Filr instances exposed to the internet do not have guest access enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ssf/a/do?p_name=ss_forum&p_action=1&action=__login
```

