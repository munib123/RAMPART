# Vulnerability: Rails/Ruby Console History - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`rails-history-exposure.yaml`)

## Description
Detects exposure of Ruby/Rails console history files (.irb_history and .pry_history) via HTTP. Leakage of these files may disclose sensitive code, credentials, or insight into application logic, increasing the risk of unauthorized access or exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.irb_history
GET {{BaseURL}}/.pry_history
```

