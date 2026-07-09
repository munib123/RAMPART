# Nuclei Template: Blockchain RPC Debug Trace Methods - Exposure
**Template ID:** blockchain-rpc-debug-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`blockchain-rpc-debug-exposure.yaml`)

## Vulnerability Information & PoC

## Description
The blockchain RPC endpoint has debug-level tracing methods enabled (debug_traceTransaction, debug_traceBlockByNumber, trace_block, trace_filter). These methods return complete EVM execution traces including opcodes, stack values, and memory contents, enabling smart contract reverse engineering and targeted attacks.

## Impact
An attacker can reconstruct the logic of unverified smart contracts, analyze internal call flows, and simulate transactions. Combined with txpool access, this enables sophisticated MEV strategies. Heavy trace calls can also cause resource exhaustion on the RPC node.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"jsonrpc":"2.0","method":"debug_traceTransaction","params":[],"id":1}
```

## Remediation
Disable all debug_* and trace_* namespace methods on public RPC endpoints. If needed for developer tooling, expose them on a separate rate-limited endpoint requiring API key authentication.

## References
- https://geth.ethereum.org/docs/developers/dapp-developer/native
- https://github.com/ledgerwatch/erigon
