# Vulnerability: Discuss.elastic.co User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`discusselasticco.yaml`)

## Description
Discuss.elastic.co user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://discuss.elastic.co/u/{{user}}
```

