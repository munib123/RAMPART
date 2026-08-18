# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4067_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4067_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 24-49 of the vulnerable file.

 *                /public/notice.php?transphrase=url_encoded_sentence_to_show
 */

define('NOCSRFCHECK', 1);
define('NOLOGIN', 1);

require '../main.inc.php';


/**
 * View
 */

if (! GETPOST('transkey', 'alphanohtml') && ! GETPOST('transphrase', 'alphanohtml'))
{
    print 'Sorry, it seems your internet connexion is off.<br>';
    print 'You need to be connected to network to use this software.<br>';
}
else
{
    $langs->load("error");
    $langs->load("other");

    if (GETPOST('transphrase', 'alphanohtml')) print GETPOST('transphrase', 'alphanohtml');
    if (GETPOST('transkey', 'alphanohtml')) print $langs->trans(GETPOST('transkey', 'alphanohtml'));
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,9 +41,8 @@
 }
 else
 {
-    $langs->load("error");
-    $langs->load("other");
+    $langs->loadLangs(array("error", "other"));
 
-    if (GETPOST('transphrase', 'alphanohtml')) print GETPOST('transphrase', 'alphanohtml');
-    if (GETPOST('transkey', 'alphanohtml')) print $langs->trans(GETPOST('transkey', 'alphanohtml'));
+    if (GETPOST('transphrase', 'alphanohtml')) print dol_escape_htmltag(GETPOST('transphrase', 'alphanohtml'));
+    elseif (GETPOST('transkey', 'alphanohtml')) print dol_escape_htmltag($langs->trans(GETPOST('transkey', 'alphanohtml')));
 }
```
