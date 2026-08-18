# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 3845_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3845_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 17-57 of the vulnerable file.

  <active>yes</active>
 </lead>
 <lead>
  <name>Michael J Rubinsky</name>
  <user>mrubinsk</user>
  <email>mrubinsk@horde.org</email>
  <active>yes</active>
 </lead>
 <date>2012-03-20</date>
 <time>11:00:03</time>
 <version>
  <release>3.0.17</release>
  <api>3.0.0</api>
 </version>
 <stability>
  <release>stable</release>
  <api>stable</api>
 </stability>
 <license uri="http://www.horde.org/licenses/gpl">GPL-2.0</license>
 <notes>
* [jan] Update Italian translation (Massimo Malabotta &lt;mmalabotta@units.it&gt;).
* [jan] Improve print styles.
* [jan] Catch if external client doesn&apos;t send LAST-MODIFIED attributes (Bug #11130).
* [jan] Don&apos;t stop agenda script if there is an error with a single user (Bug #11129).
* [jan] Update Hungarian translation (Zoltán Németh &lt;nemeth.zoltan@etit.hu&gt;).
* [jan] Show round corners only on the start and end of multi-day events (Request #11067).
 </notes>
 <contents>
  <dir baseinstalldir="/" name="/">
   <dir name="bin">
    <file name="kronolith-agenda" role="script" />
    <file name="kronolith-convert-datatree-shares-to-sql" role="script" />
    <file name="kronolith-convert-sql-shares-to-sqlng" role="script" />
    <file name="kronolith-convert-to-utc" role="script" />
    <file name="kronolith-import-icals" role="script" />
    <file name="kronolith-import-squirrelmail-calendar" role="script" />
   </dir> <!-- /bin -->
   <dir name="calendars">
    <file name="create.php" role="horde" />
    <file name="delete.php" role="horde" />
    <file name="edit.php" role="horde" />
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,7 @@
  </stability>
  <license uri="http://www.horde.org/licenses/gpl">GPL-2.0</license>
  <notes>
+* [jan] SECURITY: Fix XSS vulnerabilities in tasks view and search view (Bug #11189).
 * [jan] Update Italian translation (Massimo Malabotta &lt;mmalabotta@units.it&gt;).
 * [jan] Improve print styles.
 * [jan] Catch if external client doesn&apos;t send LAST-MODIFIED attributes (Bug #11130).
@@ -2082,6 +2083,7 @@
    <date>2012-03-20</date>
    <license uri="http://www.horde.org/licenses/gpl">GPL-2.0</license>
    <notes>
+* [jan] SECURITY: Fix XSS vulnerabilities in tasks view and search view (Bug #11189).
 * [jan] Update Italian translation (Massimo Malabotta &lt;mmalabotta@units.it&gt;).
 * [jan] Improve print styles.
 * [jan] Catch if external client doesn&apos;t send LAST-MODIFIED attributes (Bug #11130).
```
