# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 5101_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5101_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 16-56 of the vulnerable file.

  <email>jan@horde.org</email>
  <active>yes</active>
 </lead>
 <developer>
  <name>Michael Slusarz</name>
  <user>slusarz</user>
  <email>slusarz@horde.org</email>
  <active>yes</active>
 </developer>
 <date>2016-03-21</date>
 <version>
  <release>2.3.5</release>
  <api>2.3.0</api>
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
     <dir name="Text">
      <dir name="Filter">
       <file name="COPYING" role="doc" />
      </dir> <!-- /doc/Horde/Text/Filter -->
     </dir> <!-- /doc/Horde/Text -->
    </dir> <!-- /doc/Horde -->
   </dir> <!-- /doc -->
   <dir name="lib">
    <dir name="Horde">
     <dir name="Text">
      <dir name="Filter">
       <file name="Base.php" role="php" />
       <file name="Bbcode.php" role="php" />
       <file name="Cleanascii.php" role="php" />
       <file name="Cleanhtml.php" role="php" />
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,7 +33,7 @@
  </stability>
  <license uri="http://www.horde.org/licenses/lgpl21">LGPL-2.1</license>
  <notes>
-* 
+* [jan] SECURITY: Fix XSS via data:text/html content of form action and xlink attributes (Reported by Liuzhu &lt;fantasy7082@hotmail.com&gt;).
  </notes>
  <contents>
   <dir baseinstalldir="/" name="/">
@@ -1111,7 +1111,7 @@
    <date>2016-03-21</date>
    <license uri="http://www.horde.org/licenses/lgpl21">LGPL-2.1</license>
    <notes>
-* 
+* [jan] SECURITY: Fix XSS via data:text/html content of form action and xlink attributes (Reported by Liuzhu &lt;fantasy7082@hotmail.com&gt;).
    </notes>
   </release>
  </changelog>
```
