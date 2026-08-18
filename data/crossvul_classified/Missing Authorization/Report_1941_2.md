# CrossVul Fix Pair: Missing Authorization in xml
**Pair ID:** 1941_2
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1941_2`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```xml
Lines 1-26 of the vulnerable file.

<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>org.lucee</groupId>
  <artifactId>lucee</artifactId>
  <version>5.3.8.88-SNAPSHOT</version>
  <packaging>jar</packaging>

  <name>Lucee Loader Build</name>
  <description>Building the Lucee Loader JAR</description>
  <url>http://maven.lucee.org/loader/</url>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
    <maven.compiler.source>1.8</maven.compiler.source>
    <maven.compiler.target>1.8</maven.compiler.target>
    <timestamp>${maven.build.timestamp}</timestamp>
    <maven.build.timestamp.format>yyyy/MM/dd HH:mm:ss z</maven.build.timestamp.format>
    <maven.build.timestamp.zone>UTC</maven.build.timestamp.zone>
    <maven.build.timestamp.locale>en,GB</maven.build.timestamp.locale>
    <main.class>lucee.runtime.script.Main</main.class>
  </properties>

  <licenses>
    <license>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
 
   <groupId>org.lucee</groupId>
   <artifactId>lucee</artifactId>
-  <version>5.3.8.88-SNAPSHOT</version>
+  <version>5.3.8.89-SNAPSHOT</version>
   <packaging>jar</packaging>
 
   <name>Lucee Loader Build</name>
```
