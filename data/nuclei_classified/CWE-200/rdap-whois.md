# Vulnerability: RDAP WHOIS
**Classification:** CWE-200
**Source:** Nuclei Template (`rdap-whois.yaml`)

## Description
RDAP (Registration Data Access Protocol) is a standard defined by the IETF to replace the whois protocol
in queries for information about Internet resource records such as domain names, IP addresses, and ASNs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.rdap.net/domain/{{Host}}
```

