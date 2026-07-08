# Vulnerability: Blockchain RPC Debug Trace Methods - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`blockchain-rpc-debug-exposure.yaml`)

## Description
The blockchain RPC endpoint has debug-level tracing methods enabled (debug_traceTransaction, debug_traceBlockByNumber, trace_block, trace_filter). These methods return complete EVM execution traces including opcodes, stack values, and memory contents, enabling smart contract reverse engineering and targeted attacks.

## Secure Mitigation
Disable all debug_* and trace_* namespace methods on public RPC endpoints. If needed for developer tooling, expose them on a separate rate-limited endpoint requiring API key authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"jsonrpc":"2.0","method":"debug_traceTransaction","params":[],"id":1}
```

