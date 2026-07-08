# Vulnerability: OpenEthereum JSON-RPC HTTP Server Detect
**Classification:** TECH
**Source:** Nuclei Template (`openethereum-server-detect.yaml`)

## Description
OpenEthereum is the fastest, lightest, and most "secure" Ethereum client. By default OpenEthereum runs a JSON-RPC HTTP server on port 8545/TCP

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Content-Length: 66

{"method":"web3_clientVersion","params":[],"id":1,"jsonrpc":"2.0"}
```

