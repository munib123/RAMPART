# CrossVul Fix Pair: Insufficient Verification of Data Authenticity in json
**Pair ID:** 4197_6
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-345
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4197_6`)

## Vulnerability Information & PoC

## Description
Insufficient Verification of Data Authenticity - The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "webpack-subresource-integrity",
  "version": "1.5.0",
  "description": "Webpack plugin for enabling Subresource Integrity",
  "engines": {
    "node": ">=4"
  },
  "main": "index",
  "scripts": {
    "codeclimate": "docker run --interactive --tty --rm --env CODECLIMATE_CODE=\"$PWD\" --volume \"$PWD\":/code --volume /var/run/docker.sock:/var/run/docker.sock --volume /tmp/cc:/tmp/cc codeclimate/codeclimate",
    "coverage": "nyc $(npm bin)/mocha --exit --timeout 20000",
    "karma": "karma start --single-run",
    "test": "mocha --exit --timeout 20000",
    "lint": "eslint .",
    "prettier": "prettier --write '**/*.js'"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/waysact/webpack-subresource-integrity.git"
  },
  "keywords": [
    "webpack",
    "plugin",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "webpack-subresource-integrity",
-  "version": "1.5.0",
+  "version": "1.5.1",
   "description": "Webpack plugin for enabling Subresource Integrity",
   "engines": {
     "node": ">=4"
```
