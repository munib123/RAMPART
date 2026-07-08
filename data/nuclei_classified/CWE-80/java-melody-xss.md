# Vulnerability: JavaMelody - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`java-melody-xss.yaml`)

## Description
JavaMelody contains a cross-site scripting vulnerability via the monitoring parameter. An attacker can execute arbitrary script in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/monitoring?part=graph&graph=usedMemory%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

