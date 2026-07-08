# Vulnerability: Hacker News User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hacker-news.yaml`)

## Description
Hacker News user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://news.ycombinator.com/user?id={{user}}
```

