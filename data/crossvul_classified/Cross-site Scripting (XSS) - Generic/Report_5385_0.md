# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 5385_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5385_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 1-24 of the vulnerable file.

<?xml version="1.0" encoding="ISO-8859-1" ?>
<?xml-stylesheet type="text/xsl" href=""?>

<plugin>
    <name>openXInvocationTags</name>
    <displayName>Invocation Tags Plugin</displayName>
    <creationDate>2015-05-25</creationDate>
    <author>Revive Adserver</author>
    <authorEmail>revive@revive-adserver.com</authorEmail>
    <authorUrl>http://www.revive-adserver.com</authorUrl>
    <license>GNU Gneral Public License v2</license>
    <description>Plugin that provides invocation tags.</description>
    <version>1.4.4</version>
    <type>package</type>

    <install>

        <contents>
            <group name="oxInvocationTags">1</group>
        </contents>

    </install>

</plugin>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,13 +4,13 @@
 <plugin>
     <name>openXInvocationTags</name>
     <displayName>Invocation Tags Plugin</displayName>
-    <creationDate>2015-05-25</creationDate>
+    <creationDate>2016-02-23</creationDate>
     <author>Revive Adserver</author>
     <authorEmail>revive@revive-adserver.com</authorEmail>
     <authorUrl>http://www.revive-adserver.com</authorUrl>
     <license>GNU Gneral Public License v2</license>
     <description>Plugin that provides invocation tags.</description>
-    <version>1.4.4</version>
+    <version>1.4.5</version>
     <type>package</type>
 
     <install>
```
