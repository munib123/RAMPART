# Vulnerability: Nethermind JSON-RPC HTTP Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`nethermind-server-detect.yaml`)

## Description
Nethermind is a high-performance, highly configurable full Ethereum protocol execution client built on .NET that runs on Linux, Windows, and macOS, and supports Clique, Aura, and Ethash. By default Nethermind runs a JSON-RPC HTTP server on port 8545/TCP

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"method":"web3_clientVersion","params":[],"id":1,"jsonrpc":"2.0"}
```

