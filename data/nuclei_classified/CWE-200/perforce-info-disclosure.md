# Vulnerability: Perforce Server - Information Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`perforce-info-disclosure.yaml`)

## Description
Detected Perforce server exposed internal server information without authentication due to dm.info.hide being set to 0 (the default). Disclosed fields included the server version, server root path, internal server address, and license information. SSL-enforcing servers are not affected.

