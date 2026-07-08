# Vulnerability: Go Ethereum JSON-RPC HTTP Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`geth-server-detect.yaml`)

## Description
Go-ethereum (aka Geth) is an Ethereum client built in Go. Geth runs a JSON-RPC HTTP server on port 8545/TCP

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"method":"web3_clientVersion","params":[],"id":1,"jsonrpc":"2.0"}
```

