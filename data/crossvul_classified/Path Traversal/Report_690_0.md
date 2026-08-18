# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in xml
**Pair ID:** 690_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `690_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```xml
Lines 1-32 of the vulnerable file.

<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.sonatype.oss</groupId>
        <artifactId>oss-parent</artifactId>
        <version>7</version>
    </parent>
    <groupId>com.sparkjava</groupId>
    <artifactId>spark-core</artifactId>
    <packaging>bundle</packaging>
    <version>3.0.0-SNAPSHOT</version>
    <name>Spark</name>
    <description>A Sinatra inspired java web framework</description>
    <url>http://www.sparkjava.com</url>
    <licenses>
        <license>
            <name>The Apache Software License, Version 2.0</name>
            <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
            <distribution>repo</distribution>
        </license>
    </licenses>
    <scm>
        <connection>scm:git:git@github.com:perwendel/spark.git</connection>
        <developerConnection>scm:git:git@github.com:perwendel/spark.git</developerConnection>
        <url>scm:git:git@github.com:perwendel/spark.git</url>
    </scm>
    <developers>
    </developers>

    <properties>
        <java.version>1.8</java.version>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,7 +9,7 @@
     <groupId>com.sparkjava</groupId>
     <artifactId>spark-core</artifactId>
     <packaging>bundle</packaging>
-    <version>3.0.0-SNAPSHOT</version>
+    <version>2.7.2-SNAPSHOT</version>
     <name>Spark</name>
     <description>A Sinatra inspired java web framework</description>
     <url>http://www.sparkjava.com</url>
```
