# Vulnerability: Blockchain RPC - txpool_content Exposed
**Classification:** CWE-200
**Source:** Nuclei Template (`blockchain-rpc-txpool-exposed.yaml`)

## Description
The blockchain RPC endpoint exposes the txpool_content method, which returns all pending (unmined) transactions in the mempool including sender addresses, transaction data, gas prices, and values. This enables frontrunning attacks, sandwich attacks, and other MEV (Maximal Extractable Value) exploitation against users.

## Secure Mitigation
Disable txpool_content, txpool_status, and txpool_inspect on public RPC endpoints. These should only be accessible to internal validator/sequencer nodes. If needed for tooling, expose them on a separate authenticated endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}
```

