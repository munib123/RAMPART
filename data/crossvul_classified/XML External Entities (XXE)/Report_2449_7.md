# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in xml
**Pair ID:** 2449_7
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2449_7`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```xml
Lines 1-30 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.platformlambda</groupId>
    <artifactId>kafka-standalone</artifactId>

    <packaging>jar</packaging>
    <version>1.12.26</version>
    <name>Standalone kafka system for development and testing</name>
    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <repositories>
        <repository>
            <id>central</id>
            <url>http://repo1.maven.org/maven2/</url>
        </repository>
<!--        <repository>-->
<!--            <id>your-repo</id>-->
<!--            <url>https://your_repo_here/artifactory/libs-release</url>-->
<!--        </repository>-->
    </repositories>

    <dependencies>

        <dependency>
            <groupId>org.platformlambda</groupId>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,7 +7,7 @@
     <artifactId>kafka-standalone</artifactId>
 
     <packaging>jar</packaging>
-    <version>1.12.26</version>
+    <version>1.12.28</version>
     <name>Standalone kafka system for development and testing</name>
     <properties>
         <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
@@ -29,7 +29,7 @@
         <dependency>
             <groupId>org.platformlambda</groupId>
             <artifactId>platform-core</artifactId>
-            <version>1.12.26</version>
+            <version>1.12.28</version>
         </dependency>
 
         <!-- https://mvnrepository.com/artifact/org.apache.zookeeper/zookeeper -->
```
