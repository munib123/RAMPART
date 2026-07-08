# Vulnerability: Chess.com User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`chesscom.yaml`)

## Description
Chess.com user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.chess.com/member/{{user}}
```

