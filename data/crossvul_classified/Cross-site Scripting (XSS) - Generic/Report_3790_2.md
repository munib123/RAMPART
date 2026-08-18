# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 3790_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3790_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 2557-2597 of the vulnerable file.

   <stability>
    <release>stable</release>
    <api>stable</api></stability>
   <date>2012-06-26</date>
   <license uri="http://www.horde.org/licenses/gpl">GPL-2.0</license>
   <notes>
* [jan] Fix closing the compose window after redirecting (Bug #11259).
* [jan] Display correct values in permission-denied error messages (Bug #11253).
   </notes>
  </release>
  <release>
   <version>
    <release>5.0.24</release>
    <api>5.0.0</api></version>
   <stability>
    <release>stable</release>
    <api>stable</api></stability>
   <date>2012-07-20</date>
   <license uri="http://www.horde.org/licenses/gpl">GPL-2.0</license>
   <notes>
* [mms] Catch failure to add attachments because PHP&apos;s maximum allowed POST size was exceeded.
* [jan] Fix search link from portal if using dynamic view (Bug #11314).
* [mms] Fix regression in using Virtual Trash (Bug #11478; tonyb@go-concepts.com).
* [mms] Fix sending MDN notifications in traditional view (Bug #11311).
* [mms] Fix changing sort order in dynamic search mailboxes (Bug #11108).
* [mms] Fix regression in creating top-level mailbox in traditional view (Bug #11326).
* [mms] Fix spam reporting in minimal view.
   </notes>
  </release>
  <release>
   <date>2012-07-06</date>
   <time>19:14:26</time>
   <version>
    <release>6.0.0alpha1</release>
    <api>6.0.0alpha1</api>
   </version>
   <stability>
    <release>alpha</release>
    <api>alpha</api>
   </stability>
   <license uri="http://www.horde.org/licenses/gpl">GPL-2.0</license>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2574,7 +2574,8 @@
    <date>2012-07-20</date>
    <license uri="http://www.horde.org/licenses/gpl">GPL-2.0</license>
    <notes>
-* [mms] Catch failure to add attachments because PHP&apos;s maximum allowed POST size was exceeded.
+* [mms] SECURITY: Fix obscure XSS issue if uploading a file in dynamic view from the browser&apos;s local filesystem that has a filename that contains HTML.
+* [mms] Catch failure to add attachments in dynamic view because PHP&apos;s maximum allowed POST size was exceeded.
 * [jan] Fix search link from portal if using dynamic view (Bug #11314).
 * [mms] Fix regression in using Virtual Trash (Bug #11478; tonyb@go-concepts.com).
 * [mms] Fix sending MDN notifications in traditional view (Bug #11311).
```
