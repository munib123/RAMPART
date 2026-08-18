# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 4944_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4944_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 22-62 of the vulnerable file.

  <email>mrubinsk@horde.org</email>
  <active>yes</active>
 </lead>
 <lead>
  <name>Chuck Hagenbuch</name>
  <user>chuck</user>
  <email>chuck@horde.org</email>
  <active>no</active>
 </lead>
 <date>2015-10-21</date>
 <version>
  <release>5.2.9</release>
  <api>5.2.0</api>
 </version>
 <stability>
  <release>stable</release>
  <api>stable</api>
 </stability>
 <license uri="http://www.horde.org/licenses/lgpl">LGPL-2</license>
 <notes>
* 
 </notes>
 <contents>
  <dir baseinstalldir="/" name="/">
   <dir name="admin">
    <dir name="config">
     <file name="config.php" role="horde" />
     <file name="diff.php" role="horde" />
     <file name="index.php" role="horde" />
     <file name="scripts.php" role="horde" />
    </dir> <!-- /admin/config -->
    <dir name="locale">
     <dir name="de">
      <file name="help.xml" role="horde" />
     </dir> <!-- /admin/locale/de -->
     <dir name="en">
      <file name="help.xml" role="horde" />
     </dir> <!-- /admin/locale/en -->
     <dir name="es">
      <file name="help.xml" role="horde" />
     </dir> <!-- /admin/locale/es -->
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
  </stability>
  <license uri="http://www.horde.org/licenses/lgpl">LGPL-2</license>
  <notes>
-* 
+* [jan] SECURITY: Fix XSS vulnerability in menu bar exposed by only a few applications (Bug #14213).
  </notes>
  <contents>
   <dir baseinstalldir="/" name="/">
@@ -4074,7 +4074,7 @@
    <date>2015-10-20</date>
    <license uri="http://www.horde.org/licenses/lgpl">LGPL-2</license>
    <notes>
-* 
+* [jan] SECURITY: Fix XSS vulnerability in menu bar exposed by only a few applications (Bug #14213).
    </notes>
   </release>
  </changelog>
```
