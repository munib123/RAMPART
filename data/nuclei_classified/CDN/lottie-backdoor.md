# Vulnerability: Lottie Player - Backdoor
**Classification:** CDN
**Source:** Nuclei Template (`lottie-backdoor.yaml`)

## Description
Detectes vulnerable compormised version of lottie-player JS Library that were compormised with a Web3 wallet pop-up backdoor.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

