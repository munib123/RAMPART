# CrossVul Fix Pair: Deserialization of Untrusted Data in xml
**Pair ID:** 1894_3
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1894_3`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```xml
Lines 1-29 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<artifactId>server-plugin-archetype</artifactId>
	<parent>
		<groupId>io.onedev</groupId>
		<artifactId>server-plugin</artifactId>
		<version>4.0.0</version>
	</parent>
	<build>
		<resources>
		  <resource>
			<directory>src/main/resources</directory>
			<filtering>true</filtering>
			<includes>
			  <include>archetype-resources/pom.xml</include>
			</includes>
		  </resource>
		  <resource>
			<directory>src/main/resources</directory>
			<filtering>false</filtering>
			<excludes>
			  <exclude>archetype-resources/pom.xml</exclude>
			</excludes>
		  </resource>
		</resources>
		<pluginManagement>
		  <plugins>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
 	<parent>
 		<groupId>io.onedev</groupId>
 		<artifactId>server-plugin</artifactId>
-		<version>4.0.0</version>
+		<version>4.0.1</version>
 	</parent>
 	<build>
 		<resources>
```
