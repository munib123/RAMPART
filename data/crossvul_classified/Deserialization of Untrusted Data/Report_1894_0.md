# CrossVul Fix Pair: Deserialization of Untrusted Data in xml
**Pair ID:** 1894_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1894_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```xml
Lines 1-32 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>io.onedev</groupId>
		<artifactId>parent</artifactId>
		<version>1.0.5</version>
	</parent>
	<artifactId>server</artifactId>
	<version>4.0.0</version>
	<packaging>pom</packaging>
	<build>
		<finalName>${project.groupId}.${project.artifactId}-${project.version}</finalName>
		<pluginManagement>
			<plugins>
				<plugin>
					<groupId>org.antlr</groupId>
					<artifactId>antlr4-maven-plugin</artifactId>
					<version>${antlr.version}</version>
					<executions>
						<execution>
							<goals>
								<goal>antlr4</goal>
							</goals>
						</execution>
					</executions>
					<configuration>
						<sourceDirectory>${basedir}/src/main/java</sourceDirectory>
						<listener>true</listener>
						<visitor>true</visitor>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,7 +9,7 @@
 		<version>1.0.5</version>
 	</parent>
 	<artifactId>server</artifactId>
-	<version>4.0.0</version>
+	<version>4.0.1</version>
 	<packaging>pom</packaging>
 	<build>
 		<finalName>${project.groupId}.${project.artifactId}-${project.version}</finalName>
@@ -574,7 +574,7 @@
 	</repositories>
 	<properties>
 		<commons.version>1.1.21</commons.version>
-		<k8shelper.version>1.0.20</k8shelper.version>
+		<k8shelper.version>1.0.21</k8shelper.version>
 		<slf4j.version>1.7.5</slf4j.version>
 		<logback.version>1.0.11</logback.version>
 		<antlr.version>4.7.2</antlr.version>
```
