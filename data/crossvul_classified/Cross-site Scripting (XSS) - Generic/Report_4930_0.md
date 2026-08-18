# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4930_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4930_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-31 of the vulnerable file.

CodeMirror.sqlLint = function(text, updateLinting, options, cm) {

    // Skipping check if text box is empty.
    if(text.trim() == "") {
        updateLinting(cm, []);
        return;
    }

    function handleResponse(json) {
        response = JSON.parse(json);

        var found = [];
        for (var idx in response) {
            found.push({
                from: CodeMirror.Pos(
                    response[idx].fromLine, response[idx].fromColumn
                ),
                to: CodeMirror.Pos(
                    response[idx].toLine, response[idx].toColumn
                ),
                message: response[idx].message,
                severity : response[idx].severity
            });
        }

        updateLinting(cm, found);
    }

    $.ajax({
        method: "POST",
        url: "lint.php",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,9 +6,7 @@
         return;
     }
 
-    function handleResponse(json) {
-        response = JSON.parse(json);
-
+    function handleResponse(response) {
         var found = [];
         for (var idx in response) {
             found.push({
@@ -29,6 +27,7 @@
     $.ajax({
         method: "POST",
         url: "lint.php",
+        dataType: 'json',
         data: {
             sql_query: text,
             token: PMA_commonParams.get('token'),
```
