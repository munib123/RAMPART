# Nuclei Template: Generic J2EE LFI Scan Panel - Detect
**Template ID:** generic-j2ee-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`generic-j2ee-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Generic J2EE Scan panel was detected. Looks for J2EE specific LFI vulnerabilities; tries to leak the web.xml file.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

## References
- https://github.com/ilmila/J2EEScan/blob/master/src/main/java/burp/j2ee/issues/impl/LFIModule.java
- https://gist.github.com/harisec/519dc6b45c6b594908c37d9ac19edbc3
