# Vulnerability: Shiro <= 1.2.4 Deserialization Detection
**Classification:** SHIRO
**Source:** Nuclei Template (`shiro-deserialization-detection.yaml`)

## Description
This template is designed to detect the Shiro framework's default key vulnerabilities. It leverages 51 built-in Shiro keys to probe for potential vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
Cookie: JSESSIONID={{randstr}};rememberMe=123;

GET / HTTP/1.1
Host: {{Hostname}}
Cookie: JSESSIONID={{randstr}};rememberMe={{key}};
```

