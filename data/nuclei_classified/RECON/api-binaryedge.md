# Vulnerability: BinaryEdge API Test
**Classification:** RECON
**Source:** Nuclei Template (`api-binaryedge.yaml`)

## Description
BinaryEdge combines Machine Learning and Cybersecurity techniques in a custom built platform to scan, acquire and classify public Internet data. This platform scans the entire public Internet space and creates real-time threat intelligence streams and reports about your company.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.binaryedge.io/v2/user/subscription
```

