# CrossVul Fix Pair: Use of Hard-coded Credentials in json
**Pair ID:** 5225_0
**Vulnerability Class:** Use of Hard-coded Credentials
**CWE:** CWE-798
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5225_0`)

## Vulnerability Information & PoC

## Description
Use of Hard-coded Credentials - Hard-coded credentials typically create a significant hole that allows an attacker to bypass the authentication that has been configured by the product administrator.

## Vulnerable Code
```json
Lines 1-34 of the vulnerable file.

{
  "id": "bc-template-trove",
  "description": "Sets up OpenStack Trove Database Service",
  "attributes": {
    "trove": {
      "debug": false,
      "verbose": true,
      "keystone_instance": "none",
      "nova_instance": "none",
      "swift_instance": "none",
      "cinder_instance": "none",
      "rabbitmq_instance": "none",
      "volume_support": false,
      "db": {
        "password": "",
        "user": "trove",
        "database": "trove"
      }
    }
  },
  "deployment": {
    "trove": {
      "crowbar-revision": 1,
      "crowbar-applied": false,
      "element_states": {
        "trove-server": [ "readying", "ready", "applying" ]
      },
      "elements": {},
      "element_order": [
        [ "trove-server" ]
      ],
      "config": {
        "environment": "trove-base-config",
        "mode": "full",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
       "cinder_instance": "none",
       "rabbitmq_instance": "none",
       "volume_support": false,
+      "service_user": "trove",
       "db": {
         "password": "",
         "user": "trove",
@@ -22,6 +23,7 @@
     "trove": {
       "crowbar-revision": 1,
       "crowbar-applied": false,
+      "schema-revision": 2,
       "element_states": {
         "trove-server": [ "readying", "ready", "applying" ]
       },
```
