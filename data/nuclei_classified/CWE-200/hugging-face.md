# Vulnerability: Hugging face User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hugging-face.yaml`)

## Description
Hugging face user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://huggingface.co/{{user}}
```

