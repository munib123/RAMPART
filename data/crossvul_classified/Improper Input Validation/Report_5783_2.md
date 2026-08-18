# CrossVul Fix Pair: Improper Input Validation in xml
**Pair ID:** 5783_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5783_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```xml
Lines 1-28 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.1" type="file" method="upgrade">
	<name>files_joomla</name>
	<author>Joomla! Project</author>
	<authorEmail>admin@joomla.org</authorEmail>
	<authorUrl>www.joomla.org</authorUrl>
	<copyright>(C) 2005 - 2013 Open Source Matters. All rights reserved</copyright>
	<license>GNU General Public License version 2 or later; see     LICENSE.txt</license>
	<version>3.1.5</version>
	<creationDate>July 2013</creationDate>
	<description>FILES_JOOMLA_XML_DESCRIPTION</description>

	<scriptfile>administrator/components/com_admin/script.php</scriptfile>

	<update> <!-- Runs on update; New in 1.7 -->
		<schemas>
			<schemapath type="mysql">administrator/components/com_admin/sql/updates/mysql</schemapath>
			<schemapath type="sqlsrv">administrator/components/com_admin/sql/updates/sqlsrv</schemapath>
			<schemapath type="sqlazure">administrator/components/com_admin/sql/updates/sqlazure</schemapath>
			<schemapath type="postgresql">administrator/components/com_admin/sql/updates/postgresql</schemapath>
		</schemas>
	</update>

	<fileset>
		<files>
			<folder>administrator</folder>
			<folder>bin</folder>
			<folder>cache</folder>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,9 +5,9 @@
 	<authorEmail>admin@joomla.org</authorEmail>
 	<authorUrl>www.joomla.org</authorUrl>
 	<copyright>(C) 2005 - 2013 Open Source Matters. All rights reserved</copyright>
-	<license>GNU General Public License version 2 or later; see     LICENSE.txt</license>
+	<license>GNU General Public License version 2 or later; see LICENSE.txt</license>
 	<version>3.1.5</version>
-	<creationDate>July 2013</creationDate>
+	<creationDate>August 2013</creationDate>
 	<description>FILES_JOOMLA_XML_DESCRIPTION</description>
 
 	<scriptfile>administrator/components/com_admin/script.php</scriptfile>
```
