# Vulnerability: Smartbi windowunloading Interface - Deserialization
**Classification:** CWE-94,CWE-502
**Source:** Nuclei Template (`smartbi-deserialization.yaml`)

## Description
The Smartbi big data analysis platform has a remote command execution vulnerability. An unauthenticated remote attacker can use the stub interface to construct a request to bypass patch restrictions and then control the JDBC URL, which can ultimately lead to remote code execution or information leakage.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

className=UserService&methodName=isLogged&params=[]
```

