# Vulnerability: useanvil.com Login Check
**Classification:** CLOUD
**Source:** Nuclei Template (`avnil-pdf-generator-check.yaml`)

## Description
Checks for a valid avnil pdf generator account.

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://graphql.useanvil.com/ HTTP/1.1
Host: graphql.useanvil.com
Content-Length: 367
Content-Type: application/json

{"operationName":"LoginMutation","variables":{"email":"{{username}}","password":"{{password}}"},"query":"mutation LoginMutation($email: String, $password: String) {\n  login(email: $email, password: $password) {\n    eid\n    firstName\n    lastName\n    email\n    preferences {\n      require2FA\n      __typename\n    }\n    extra\n    __typename\n  }\n}\n"}
```

