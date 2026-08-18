# CrossVul Fix Pair: Deserialization of Untrusted Data in xml
**Pair ID:** 1894_5
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1894_5`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```xml
Lines 1-20 of the vulnerable file.

<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<artifactId>server-plugin-buildspec-gradle</artifactId>
	<parent>
		<groupId>io.onedev</groupId>
		<artifactId>server-plugin</artifactId>
		<version>4.0.0</version>
	</parent>
	<dependencies>
		<dependency>
			<groupId>io.onedev</groupId>
			<artifactId>server-plugin-report-html</artifactId>
			<version>${project.version}</version>
		</dependency>
	</dependencies>
	<properties>
		<moduleClass>io.onedev.server.plugin.buildspec.gradle.GradleModule</moduleClass>
	</properties>
</project>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,7 @@
 	<parent>
 		<groupId>io.onedev</groupId>
 		<artifactId>server-plugin</artifactId>
-		<version>4.0.0</version>
+		<version>4.0.1</version>
 	</parent>
 	<dependencies>
 		<dependency>
```
