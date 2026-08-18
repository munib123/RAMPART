# CrossVul Fix Pair: Credentials Management Errors in javascript
**Pair ID:** 4912_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4912_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```javascript
Lines 305-345 of the vulnerable file.

    if (! $form.find('input:hidden').is('#ajax_request_hidden')) {
        $form.append('<input type="hidden" id="ajax_request_hidden" name="ajax_request" value="true" />');
    }
}

/**
 * Generate a new password and copy it to the password input areas
 *
 * @param passwd_form object   the form that holds the password fields
 *
 * @return boolean  always true
 */
function suggestPassword(passwd_form)
{
    // restrict the password to just letters and numbers to avoid problems:
    // "editors and viewers regard the password as multiple words and
    // things like double click no longer work"
    var pwchars = "abcdefhjmnpqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWYXZ";
    var passwordlength = 16;    // do we want that to be dynamic?  no, keep it simple :)
    var passwd = passwd_form.generated_pw;
    passwd.value = '';

    for (var i = 0; i < passwordlength; i++) {
        passwd.value += pwchars.charAt(Math.floor(Math.random() * pwchars.length));
    }
    passwd_form.text_pma_pw.value = passwd.value;
    passwd_form.text_pma_pw2.value = passwd.value;
    return true;
}

/**
 * Version string to integer conversion.
 */
function parseVersionString(str)
{
    if (typeof(str) != 'string') { return false; }
    var add = 0;
    // Parse possible alpha/beta/rc/
    var state = str.split('-');
    if (state.length >= 2) {
        if (state[1].substr(0, 2) == 'rc') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -322,11 +322,28 @@
     var pwchars = "abcdefhjmnpqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWYXZ";
     var passwordlength = 16;    // do we want that to be dynamic?  no, keep it simple :)
     var passwd = passwd_form.generated_pw;
+    var randomWords = new Int32Array(passwordlength);
+
     passwd.value = '';
 
+    // First we're going to try to use a built-in CSPRNG
+    if (window.crypto && window.crypto.getRandomValues) {
+        window.crypto.getRandomValues(randomWords);
+    }
+    // Because of course IE calls it msCrypto instead of being standard
+    else if (window.msCrypto && window.msCrypto.getRandomValues) {
+        window.msCrypto.getRandomValues(randomWords);
+    } else {
+        // Fallback to Math.random
+        for (var i = 0; i < passwordlength; i++) {
+            randomWords[i] = Math.floor(Math.random() * pwchars.length);
+        }
+    }
+
     for (var i = 0; i < passwordlength; i++) {
-        passwd.value += pwchars.charAt(Math.floor(Math.random() * pwchars.length));
-    }
+        passwd.value += pwchars.charAt(Math.abs(randomWords[i]) % pwchars.length);
+    }
+
     passwd_form.text_pma_pw.value = passwd.value;
     passwd_form.text_pma_pw2.value = passwd.value;
     return true;
```
