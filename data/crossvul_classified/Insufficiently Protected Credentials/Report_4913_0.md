# CrossVul Fix Pair: Credentials Management Errors in javascript
**Pair ID:** 4913_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4913_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```javascript
Lines 302-342 of the vulnerable file.

 */
function PMA_prepareForAjaxRequest($form)
{
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
    var randomWords = new Int32Array(passwordlength);

    passwd.value = '';

    // First we're going to try to use a built-in CSPRNG
    if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(randomWords);
    }
    // Because of course IE calls it msCrypto instead of being standard
    else if (window.msCrypto && window.msCrypto.getRandomValues) {
        window.msCrypto.getRandomValues(randomWords);
    } else {
        // Fallback to Math.random
        for (var i = 0; i < passwordlength; i++) {
            randomWords[i] = Math.floor(Math.random() * pwchars.length);
        }
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -319,7 +319,7 @@
     // restrict the password to just letters and numbers to avoid problems:
     // "editors and viewers regard the password as multiple words and
     // things like double click no longer work"
-    var pwchars = "abcdefhjmnpqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWYXZ";
+    var pwchars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWYXZ";
     var passwordlength = 16;    // do we want that to be dynamic?  no, keep it simple :)
     var passwd = passwd_form.generated_pw;
     var randomWords = new Int32Array(passwordlength);
```
