# Vulnerability: Bitbucket OAuth Credentials Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`bitbucket-oauth-exposure.yaml`)

## Description
Detects exposed auth.json files containing Bitbucket OAuth credentials

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth.json
GET {{BaseURL}}/.auth.json
GET {{BaseURL}}/config/auth.json
GET {{BaseURL}}/configs/auth.json
GET {{BaseURL}}/configuration/auth.json
GET {{BaseURL}}/api/auth.json
GET {{BaseURL}}/app/auth.json
GET {{BaseURL}}/assets/auth.json
GET {{BaseURL}}/data/auth.json
GET {{BaseURL}}/files/auth.json
GET {{BaseURL}}/public/auth.json
GET {{BaseURL}}/static/auth.json
GET {{BaseURL}}/uploads/auth.json
GET {{BaseURL}}/backup/auth.json
GET {{BaseURL}}/backups/auth.json
GET {{BaseURL}}/tmp/auth.json
GET {{BaseURL}}/temp/auth.json
GET {{BaseURL}}/cache/auth.json
GET {{BaseURL}}/logs/auth.json
GET {{BaseURL}}/admin/auth.json
GET {{BaseURL}}/administrator/auth.json
GET {{BaseURL}}/src/auth.json
GET {{BaseURL}}/source/auth.json
GET {{BaseURL}}/www/auth.json
GET {{BaseURL}}/web/auth.json
GET {{BaseURL}}/site/auth.json
GET {{BaseURL}}/sites/auth.json
GET {{BaseURL}}/private/auth.json
GET {{BaseURL}}/secure/auth.json
GET {{BaseURL}}/secret/auth.json
GET {{BaseURL}}/secrets/auth.json
GET {{BaseURL}}/env/auth.json
GET {{BaseURL}}/environment/auth.json
GET {{BaseURL}}/test/auth.json
GET {{BaseURL}}/tests/auth.json
GET {{BaseURL}}/dev/auth.json
GET {{BaseURL}}/development/auth.json
GET {{BaseURL}}/staging/auth.json
GET {{BaseURL}}/prod/auth.json
GET {{BaseURL}}/production/auth.json
GET {{BaseURL}}/includes/auth.json
GET {{BaseURL}}/include/auth.json
GET {{BaseURL}}/lib/auth.json
GET {{BaseURL}}/libs/auth.json
GET {{BaseURL}}/library/auth.json
GET {{BaseURL}}/vendor/auth.json
GET {{BaseURL}}/vendors/auth.json
GET {{BaseURL}}/node_modules/auth.json
GET {{BaseURL}}/storage/auth.json
GET {{BaseURL}}/database/auth.json
GET {{BaseURL}}/db/auth.json
GET {{BaseURL}}/auth/auth.json
GET {{BaseURL}}/authentication/auth.json
GET {{BaseURL}}/oauth/auth.json
GET {{BaseURL}}/keys/auth.json
GET {{BaseURL}}/credentials/auth.json
GET {{BaseURL}}/creds/auth.json
```

