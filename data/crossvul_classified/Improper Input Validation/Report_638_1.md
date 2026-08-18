# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 638_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `638_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "aws-lambda-multipart-parser",
  "version": "0.1.1",
  "description": "Parser of multipart/form-data requests for AWS Lambda",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/myshenin/aws-lambda-multipart-parser.git"
  },
  "author": "Anton Myshenin",
  "license": "MIT",
  "bugs": {
    "url": "https://github.com/myshenin/aws-lambda-multipart-parser/issues"
  },
  "homepage": "https://github.com/myshenin/aws-lambda-multipart-parser#readme",
  "keywords": [
    "aws",
    "lambda",
    "multipart",
    "multipart/form-data",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "aws-lambda-multipart-parser",
-  "version": "0.1.1",
+  "version": "0.1.2",
   "description": "Parser of multipart/form-data requests for AWS Lambda",
   "main": "index.js",
   "scripts": {
```
