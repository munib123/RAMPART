# CrossVul Fix Pair: Insufficiently Protected Credentials in json
**Pair ID:** 4317_1
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4317_1`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "nats.ws",
  "version": "1.0.0-110",
  "description": "WebSocket NATS client",
  "main": "nats.mjs",
  "types": "nats.d.ts",
  "files": [
    "examples/",
    "OWNERS.md",
    "CODE-OF-CONDUCT.md",
    "LICENSE",
    "nats.d.ts"
  ],
  "scripts": {
    "setup": "curl -fsSL https://deno.land/x/install/install.sh | sh",
    "build": "deno run --allow-all --unstable --reload src/mod.ts && deno bundle --unstable src/mod.ts ./nats.mjs",
    "prepack": "npm run build",
    "fmt": "deno fmt src/*.ts examples/*.js test/*.js test/*/*.js",
    "start-tls-nats": "cd examples && ../nats-server -DV -c tls.conf",
    "start-nats": "cd examples && ../nats-server -c nontls.conf",
    "start-http": "deno run --allow-all --unstable https://raw.githubusercontent.com/denoland/deno/master/std/http/file_server.ts .",
    "start-https": "deno run --allow-all --unstable https://raw.githubusercontent.com/denoland/deno/master/std/http/file_server.ts --port 4607 --cert ./certs/cert.pem --key ./certs/key.pem --host localhost .",
    "install-certs": "env CAROOT=./certs mkcert -cert-file ./certs/cert.pem -key-file ./certs/key.pem -install localhost 127.0.0.1 ::1",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "nats.ws",
-  "version": "1.0.0-110",
+  "version": "1.0.0-111",
   "description": "WebSocket NATS client",
   "main": "nats.mjs",
   "types": "nats.d.ts",
```
