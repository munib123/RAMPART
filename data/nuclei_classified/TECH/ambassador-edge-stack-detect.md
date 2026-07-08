# Vulnerability: Ambassador Edge Stack - Detect
**Classification:** TECH
**Source:** Nuclei Template (`ambassador-edge-stack-detect.yaml`)

## Description
Ambassador Edge Stack is a Kubernetes-native API Gateway that delivers the scalability, security, and simplicity for some of the world's largest Kubernetes installations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

