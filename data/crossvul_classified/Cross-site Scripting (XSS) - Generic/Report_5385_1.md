# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 5385_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5385_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 1-27 of the vulnerable file.

<?xml version="1.0" encoding="ISO-8859-1" ?>
<?xml-stylesheet type="text/xsl" href=""?>

<plugin>
    <name>oxInvocationTags</name>
    <displayName>Invocation Tags Plugin</displayName>
    <creationDate>2015-05-25</creationDate>
    <author>Revive Adserver</author>
    <authorEmail>revive@revive-adserver.com</authorEmail>
    <authorUrl>http://www.revive-adserver.com</authorUrl>
    <license>GNU Gneral Public License v2</license>
    <description>Plugin that provides invocation tags for displaying banners on websites.</description>
    <version>1.4.4</version>
    <oxversion>3.2.0-beta-rc3</oxversion>
    <extends>invocationTags</extends>

    <install>
        <files>
            <file path="{MODULEPATH}invocationTags/oxInvocationTags/">adframe.class.php</file>
            <file path="{MODULEPATH}invocationTags/oxInvocationTags/">adjs.class.php</file>
            <file path="{MODULEPATH}invocationTags/oxInvocationTags/">adlayer.class.php</file>
            <file path="{MODULEPATH}invocationTags/oxInvocationTags/">adview.class.php</file>
            <file path="{MODULEPATH}invocationTags/oxInvocationTags/">adviewnocookies.class.php</file>
            <file path="{MODULEPATH}invocationTags/oxInvocationTags/">async.class.php</file>
            <file path="{MODULEPATH}invocationTags/oxInvocationTags/">local.class.php</file>
            <file path="{MODULEPATH}invocationTags/oxInvocationTags/">popup.class.php</file>
            <file path="{MODULEPATH}invocationTags/oxInvocationTags/">spc.class.php</file>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,13 +4,13 @@
 <plugin>
     <name>oxInvocationTags</name>
     <displayName>Invocation Tags Plugin</displayName>
-    <creationDate>2015-05-25</creationDate>
+    <creationDate>2016-02-23</creationDate>
     <author>Revive Adserver</author>
     <authorEmail>revive@revive-adserver.com</authorEmail>
     <authorUrl>http://www.revive-adserver.com</authorUrl>
     <license>GNU Gneral Public License v2</license>
     <description>Plugin that provides invocation tags for displaying banners on websites.</description>
-    <version>1.4.4</version>
+    <version>1.4.5</version>
     <oxversion>3.2.0-beta-rc3</oxversion>
     <extends>invocationTags</extends>
 
```
