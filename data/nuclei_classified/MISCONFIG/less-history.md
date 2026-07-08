# Vulnerability: Less History - File Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`less-history.yaml`)

## Description
LESSHST file is a Less History File. LESSHST file is a Less History File. Less is a terminal pager program on Unix, Windows, and Unix-like systems used to view (but not change) the contents of a text file one screen at a time.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.lesshst
```

