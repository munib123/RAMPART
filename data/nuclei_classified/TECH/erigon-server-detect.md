# Vulnerability: Erigon JSON-RPC HTTP Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`erigon-server-detect.yaml`)

## Description
Erigon is an implementation of Ethereum (execution layer with embeddable consensus layer). By default Erigon runs a JSON-RPC HTTP server on port 8545/TCP

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"method":"web3_clientVersion","params":[],"id":1,"jsonrpc":"2.0"}
```

