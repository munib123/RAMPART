# Vulnerability: Adobe AEM JCR Compare Exposure
**Classification:** AEM
**Source:** Nuclei Template (`aem-jcr-exposure.yaml`)

## Description
Detected an exposed Adobe AEM JCR compare functionality that was accessible without proper authorization. This exposure may have allowed attackers to infer repository structure or sensitive content through comparison operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jcr:content.json
GET {{BaseURL}}/etc/replication/agents.author/publish/jcr:content.json
```

