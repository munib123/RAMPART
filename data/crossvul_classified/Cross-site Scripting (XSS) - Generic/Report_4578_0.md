# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 4578_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4578_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 1-11 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8" ?>
<module>
    <name>ps_socialfollow</name>
    <displayName><![CDATA[Social media follow links]]></displayName>
    <version><![CDATA[1.0]]></version>
    <description><![CDATA[Allows you to add information about your brand&#039;s social networking accounts.]]></description>
    <author><![CDATA[PrestaShop]]></author>
    <is_configurable>1</is_configurable>
    <need_instance>1</need_instance>
	<limited_countries></limited_countries>
</module>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,9 +2,10 @@
 <module>
     <name>ps_socialfollow</name>
     <displayName><![CDATA[Social media follow links]]></displayName>
-    <version><![CDATA[1.0]]></version>
+    <version><![CDATA[2.1.0]]></version>
     <description><![CDATA[Allows you to add information about your brand&#039;s social networking accounts.]]></description>
     <author><![CDATA[PrestaShop]]></author>
+    <tab><![CDATA[]]></tab>
     <is_configurable>1</is_configurable>
     <need_instance>1</need_instance>
 	<limited_countries></limited_countries>
```
