# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 883_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `883_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 1-30 of the vulnerable file.

<?xml version="1.0"?>
<document xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://maven.apache.org/changes/1.0.0"
			 xsi:schemaLocation="http://maven.apache.org/changes/1.0.0 ./changes.xsd">
	<properties>
		<author>James Agnew</author>
		<title>HAPI FHIR Changelog</title>
	</properties>
	<body>
		<release version="3.8.0" date="TBD" description="Hippo">
			<action type="add">
				The version of a few dependencies have been bumped to the
				latest versions (dependent HAPI modules listed in brackets):
				<![CDATA[
				<ul>
					<li>Guava (base): 25-jre -&gt; 27.1-jre</li>
					<li>Hibernate (JPA): 5.4.1 -&gt; 5.4.2</li>
					<li>Jackson (JPA): 2.9.7 -&gt; 2.9.8</li>
					<li>Spring (JPA): 5.1.3.RELEASE -&gt; 5.1.6.RELEASE</li>
					<li>Spring-Data (JPA): 2.1.3.RELEASE -&gt; 2.1.6.RELEASE</li>
					<li>Caffeine (JPA): 2.6.2 -&gt; 2.7.0</li>
					<li>JANSI (CLI): 1.16 -&gt; 1.17.1</li>
					<!--<li>Jetty (CLI): 9.4.14.v20181114 -&gt; 9.4.17.v20190418</li>-->
				</ul>
				]]>
			</action>
			<action type="add">
				In Servers that are configured to support extended mode
				<![CDATA[<code>_elements</code>]]> parameters, it is now possible to
				use the :exclude modifier to exclude entire resource types.
			</action>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,11 @@
 	</properties>
 	<body>
 		<release version="3.8.0" date="TBD" description="Hippo">
+			<action type="fix">
+				A potential security vulnerability in the hapi-fhir-testpage-overlay project was corrected: A URL
+				parameter was not being correctly escaped, leading to a potential XSS vulnerabnility. A big thanks to
+				Mudit Punia and Dushyant Garg for reporting this.
+			</action>
 			<action type="add">
 				The version of a few dependencies have been bumped to the
 				latest versions (dependent HAPI modules listed in brackets):
```
