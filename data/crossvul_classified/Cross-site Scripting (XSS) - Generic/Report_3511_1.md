# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3511_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3511_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 155-195 of the vulnerable file.

 * @param   var     lock        variable which holds the lock for this element
 *                              or true, if no lock exists
 * @param   boolean only_once   if true this is only done once
 *                              f.e. only on first focus
 */
function selectContent( element, lock, only_once ) {
    if ( only_once && only_once_elements[element.name] ) {
        return;
    }

    only_once_elements[element.name] = true;

    if ( lock  ) {
        return;
    }

    element.select();
}

/**
 * Displays a confirmation box before to submit a "DROP/DELETE/ALTER" query.
 * This function is called while clicking links
 *
 * @param   object   the link
 * @param   object   the sql query to submit
 *
 * @return  boolean  whether to run the query or not
 */
function confirmLink(theLink, theSqlQuery)
{
    // Confirmation is not required in the configuration file
    // or browser is Opera (crappy js implementation)
    if (PMA_messages['strDoYouReally'] == '' || typeof(window.opera) != 'undefined') {
        return true;
    }

    var is_confirmed = confirm(PMA_messages['strDoYouReally'] + ' :\n' + theSqlQuery);
    if (is_confirmed) {
        if ( typeof(theLink.href) != 'undefined' ) {
            theLink.href += '&is_js_confirmed=1';
        } else if ( typeof(theLink.form) != 'undefined' ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -172,7 +172,7 @@
 }
 
 /**
- * Displays a confirmation box before to submit a "DROP/DELETE/ALTER" query.
+ * Displays a confirmation box before submitting a "DROP/DELETE/ALTER" query.
  * This function is called while clicking links
  *
  * @param   object   the link
@@ -1657,7 +1657,7 @@
         /**
          * @var question    String containing the question to be asked for confirmation
          */
-        var question = PMA_messages['strDropDatabaseStrongWarning'] + '\n' + PMA_messages['strDoYouReally'] + ' :\n' + 'DROP DATABASE ' + window.parent.db;
+        var question = PMA_messages['strDropDatabaseStrongWarning'] + '\n' + PMA_messages['strDoYouReally'] + ' :\n' + 'DROP DATABASE ' + escapeHtml(window.parent.db);
 
         $(this).PMA_confirm(question, $(this).attr('href') ,function(url) {
 
@@ -2287,3 +2287,14 @@
 
 }) // end of $(document).ready()
 
+/**
+ * HTML escaping
+ */
+function escapeHtml(unsafe) {
+    return unsafe
+        .replace(/&/g, "&amp;")
+        .replace(/</g, "&lt;")
+        .replace(/>/g, "&gt;")
+        .replace(/"/g, "&quot;")
+        .replace(/'/g, "&#039;");
+}
```
