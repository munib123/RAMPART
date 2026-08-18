# CrossVul Fix Pair: Deserialization of Untrusted Data in xml
**Pair ID:** 1894_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1894_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```xml
Lines 1-29 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<artifactId>server-plugin</artifactId>
	<packaging>pom</packaging>
	<parent>
		<groupId>io.onedev</groupId>
		<artifactId>server</artifactId>
		<version>4.0.0</version>
	</parent>
	<dependencies>
		<dependency>
			<groupId>io.onedev</groupId>
			<artifactId>server-core</artifactId>
			<version>${project.version}</version>
		</dependency>
	</dependencies>
	<modules>
		<module>server-plugin-archetype</module>
		<module>server-plugin-report-html</module>
		<module>server-plugin-executor-kubernetes</module>
		<module>server-plugin-executor-docker</module>
		<module>server-plugin-buildspec-maven</module>
    	<module>server-plugin-buildspec-gradle</module>
    	<module>server-plugin-buildspec-node</module>
	    <module>server-plugin-authenticator-ldap</module>
	    <module>server-plugin-sso-openid</module>
    	<module>server-plugin-report-markdown</module>
  </modules>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
 	<parent>
 		<groupId>io.onedev</groupId>
 		<artifactId>server</artifactId>
-		<version>4.0.0</version>
+		<version>4.0.1</version>
 	</parent>
 	<dependencies>
 		<dependency>
```
