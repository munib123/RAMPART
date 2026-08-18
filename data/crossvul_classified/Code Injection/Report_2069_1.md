# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in xml
**Pair ID:** 2069_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2069_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```xml
Lines 9-50 of the vulnerable file.

  <name>Chuck Hagenbuch</name>
  <user>chuck</user>
  <email>chuck@horde.org</email>
  <active>yes</active>
 </lead>
 <lead>
  <name>Jan Schneider</name>
  <user>jan</user>
  <email>jan@horde.org</email>
  <active>yes</active>
 </lead>
 <developer>
  <name>Michael Slusarz</name>
  <user>slusarz</user>
  <email>slusarz@horde.org</email>
  <active>yes</active>
 </developer>
 <date>2013-05-06</date>
 <time>19:34:35</time>
 <version>
  <release>2.2.3</release>
  <api>2.2.0</api>
 </version>
 <stability>
  <release>stable</release>
  <api>stable</api>
 </stability>
 <license uri="http://www.horde.org/licenses/lgpl21">LGPL-2.1</license>
 <notes>
* 
 </notes>
 <contents>
  <dir baseinstalldir="/" name="/">
   <dir name="doc">
    <dir name="Horde">
     <dir name="Util">
      <file name="COPYING" role="doc" />
      <file name="UPGRADING" role="doc" />
     </dir> <!-- /doc/Horde/Util -->
    </dir> <!-- /doc/Horde -->
   </dir> <!-- /doc -->
   <dir name="lib">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,8 +26,8 @@
  <date>2013-05-06</date>
  <time>19:34:35</time>
  <version>
-  <release>2.2.3</release>
-  <api>2.2.0</api>
+  <release>2.3.0</release>
+  <api>2.3.0</api>
  </version>
  <stability>
   <release>stable</release>
@@ -35,7 +35,7 @@
  </stability>
  <license uri="http://www.horde.org/licenses/lgpl21">LGPL-2.1</license>
  <notes>
-* 
+* [mms] SECURITY: &apos;_formvars&apos; form input must now be JSON encoded, not PHP serialized.
  </notes>
  <contents>
   <dir baseinstalldir="/" name="/">
@@ -117,6 +117,9 @@
     <name>iconv</name>
    </extension>
    <extension>
+    <name>json</name>
+   </extension>
+   <extension>
     <name>mbstring</name>
    </extension>
    <extension>
@@ -619,15 +622,15 @@
   </release>
   <release>
    <version>
-    <release>2.2.3</release>
-    <api>2.2.0</api></version>
+    <release>2.3.0</release>
+    <api>2.3.0</api></version>
    <stability>
     <release>stable</release>
     <api>stable</api></stability>
    <date>2013-05-06</date>
    <license uri="http://www.horde.org/licenses/lgpl21">LGPL-2.1</license>
    <notes>
-* 
+* [mms] SECURITY: &apos;_formvars&apos; form input must now be JSON encoded, not PHP serialized.
    </notes>
   </release>
  </changelog>
```
