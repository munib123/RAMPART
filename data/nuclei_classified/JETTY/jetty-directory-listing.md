# Vulnerability: Eclipse Jetty - Directory Listing Enabled
**Classification:** JETTY
**Source:** Nuclei Template (`jetty-directory-listing.yaml`)

## Description
Eclipse Jetty server has directory listing enabled, which exposes the directory structure and file names to unauthenticated users. This can reveal sensitive files, backup files, configuration files, and aid attackers in reconnaissance.

## Secure Mitigation
Disable directory listing by setting dirAllowed to false in the DefaultServlet configuration or by setting allowDirectoryListing to false in WebAppContext. Add index files (index.html) to directories that should not list contents.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/static/
GET {{BaseURL}}/resources/
GET {{BaseURL}}/assets/
GET {{BaseURL}}/files/
```

