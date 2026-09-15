# Nuclei Template: Blockchain RPC - txpool_content Exposed
**Template ID:** blockchain-rpc-txpool-exposed
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`blockchain-rpc-txpool-exposed.yaml`)

## Vulnerability Information & PoC

## Description
The blockchain RPC endpoint exposes the txpool_content method, which returns all pending (unmined) transactions in the mempool including sender addresses, transaction data, gas prices, and values. This enables frontrunning attacks, sandwich attacks, and other MEV (Maximal Extractable Value) exploitation against users.

## Impact
An attacker can monitor pending transactions in real-time to perform frontrunning (executing trades before victims), sandwich attacks (placing buy/sell orders around a victim's swap), and general mempool surveillance. This directly impacts every user performing DeFi transactions on the chain.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}
```

## Remediation
Disable txpool_content, txpool_status, and txpool_inspect on public RPC endpoints. These should only be accessible to internal validator/sequencer nodes. If needed for tooling, expose them on a separate authenticated endpoint.

## References
- https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-txpool
- https://ethereum.org/en/developers/docs/mev/
