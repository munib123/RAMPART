# Vulnerability: D-Link DSL2600U - Unauthenticated rom-0 Configuration Disclosure
**Classification:** Uncategorized
**Source:** Nuclei Template (`dlink-dsl2600u-rom0-disclosure.yaml`)

## Description
Detected D-Link DSL2600U router was found to expose the /rom-0 binary configuration file without authentication. The file contains the admin password stored as LZS-compressed data at byte offset 8568 (0x2178) with no plaintext copy anywhere in the binary.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /rom-0 HTTP/1.1
Host: {{Hostname}}
```

