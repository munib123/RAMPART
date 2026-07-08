# Vulnerability: Besu JSON-RPC HTTP Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`besu-server-detect.yaml`)

## Description
Besu is an open source Ethereum client developed under the Apache 2.0 license and written in Java. By default Besu runs a JSON-RPC HTTP server on port 8545/TCP

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"method":"web3_clientVersion","params":[],"id":1,"jsonrpc":"2.0"}
```

