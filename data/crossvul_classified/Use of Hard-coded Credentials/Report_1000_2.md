# CrossVul Fix Pair: Use of Hard-coded Credentials in json
**Pair ID:** 1000_2
**Vulnerability Class:** Use of Hard-coded Credentials
**CWE:** CWE-798
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1000_2`)

## Vulnerability Information & PoC

## Description
Use of Hard-coded Credentials - Hard-coded credentials typically create a significant hole that allows an attacker to bypass the authentication that has been configured by the product administrator.

## Vulnerable Code
```json
Lines 94-134 of the vulnerable file.

        }
      ],
      "realmRoles": [
        "admin", "uma_authorization"
      ],
      "clientRoles": {
        "realm-management": [
          "realm-admin"
        ],
        "photoz-restful-api": [
          "manage-albums"
        ],
        "account": [
          "manage-account"
        ]
      }
    },
    {
      "username": "service-account-photoz-restful-api",
      "enabled": true,
      "email": "service-account-photoz-restful-api@placeholder.org",
      "serviceAccountClientId": "photoz-restful-api",
      "clientRoles": {
        "photoz-restful-api" : ["uma_protection"]
      }
    }
  ],
  "roles": {
    "realm": [
      {
        "name": "user",
        "description": "User privileges"
      },
      {
        "name": "admin",
        "description": "Administrator privileges"
      }
    ]
  },
  "clients": [
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,7 +111,6 @@
     {
       "username": "service-account-photoz-restful-api",
       "enabled": true,
-      "email": "service-account-photoz-restful-api@placeholder.org",
       "serviceAccountClientId": "photoz-restful-api",
       "clientRoles": {
         "photoz-restful-api" : ["uma_protection"]
```
