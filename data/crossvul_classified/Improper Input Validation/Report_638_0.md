# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 638_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `638_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-30 of the vulnerable file.

function getValueIgnoringKeyCase(obj, lookedKey) {
    return Object.keys(obj)
        .map(presentKey => presentKey.toLowerCase() === lookedKey.toLowerCase() ? obj[presentKey] : null)
        .filter(item => item)[0];
}

module.exports.parse = (event, spotText) => {
    const boundary = getValueIgnoringKeyCase(event.headers, 'Content-Type').split('=')[1];
    const body = (event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('binary') : event.body)
        .split(new RegExp(boundary))
        .filter(item => item.match(/Content-Disposition/))
        .map((item) => {
            if (item.match(/filename/)) {
                const result = {};
                result[
                    item
                        .match(/name="[a-zA-Z_]+([a-zA-Z0-9_]*)"/)[0]
                        .split('=')[1]
                        .match(/[a-zA-Z_]+([a-zA-Z0-9_]*)/)[0]
                ] = {
                        type: 'file',
                        filename: item
                            .match(/filename="[\w-\. ]+"/)[0]
                            .split('=')[1]
                            .match(/[\w-\.]+/)[0],
                        contentType: item
                            .match(/Content-Type: .+\r\n\r\n/)[0]
                            .replace(/Content-Type: /, '')
                            .replace(/\r\n\r\n/, ''),
                        content: (spotText && item
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,7 +7,7 @@
 module.exports.parse = (event, spotText) => {
     const boundary = getValueIgnoringKeyCase(event.headers, 'Content-Type').split('=')[1];
     const body = (event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('binary') : event.body)
-        .split(new RegExp(boundary))
+        .split(boundary)
         .filter(item => item.match(/Content-Disposition/))
         .map((item) => {
             if (item.match(/filename/)) {
```
