# CrossVul Fix Pair: Deserialization of Untrusted Data in json
**Pair ID:** 381_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `381_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "tecnickcom/tcpdf",
  "version": "6.2.16",
  "homepage": "http://www.tcpdf.org/",
  "type": "library",
  "description": "TCPDF is a PHP class for generating PDF documents and barcodes.",
  "keywords": [
    "PDF",
    "tcpdf",
    "PDFD32000-2008",
    "qrcode",
    "datamatrix",
    "pdf417",
    "barcodes"
  ],
  "license": "LGPL-3.0",
  "authors": [
    {
      "name": "Nicola Asuni",
      "email": "info@tecnick.com",
      "role": "lead"
    }
  ],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "tecnickcom/tcpdf",
-  "version": "6.2.16",
+  "version": "6.2.26",
   "homepage": "http://www.tcpdf.org/",
   "type": "library",
   "description": "TCPDF is a PHP class for generating PDF documents and barcodes.",
```
