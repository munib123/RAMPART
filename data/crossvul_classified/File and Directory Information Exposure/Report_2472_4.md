# CrossVul Fix Pair: Files or Directories Accessible to External Parties in xml
**Pair ID:** 2472_4
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2472_4`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```xml
Lines 62-102 of the vulnerable file.

        <tag>HEAD</tag>
    </scm>

    <prerequisites>
        <maven>3.0.0</maven>
    </prerequisites>

    <properties>
        <autoVersionSubmodules>true</autoVersionSubmodules>
        <min.jdk.version>1.8</min.jdk.version>
        <max.jdk.version>1.10</max.jdk.version>
        <source.jdk.version>${min.jdk.version}</source.jdk.version>
        <target.jdk.version>${min.jdk.version}</target.jdk.version>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
        <maven.build.timestamp.format>yyyyMMddHHmm</maven.build.timestamp.format>

        <!-- dependency versions -->
        <version.antlr4>4.8-1</version.antlr4>
        <version.logback>1.2.3</version.logback>
        <version.jetty>9.4.26.v20200117</version.jetty>
        <version.restassured>4.2.0</version.restassured>
        <version.jackson>2.10.3</version.jackson>
        <version.jersey>2.30</version.jersey>
        <version.junit>5.6.0</version.junit>
        <hibernate3.version>3.6.10.Final</hibernate3.version>
        <version.mysql>8.0.19</version.mysql>
        <hibernate5.version>5.4.2.Final</hibernate5.version>

        <!-- TODO: Need to update locations to be relative to the projects using them -->
        <parent.pom.dir>${project.basedir}/..</parent.pom.dir>
        <checkstyle.config.location>${parent.pom.dir}/checkstyle-style.xml</checkstyle.config.location>
        <checkstyle.suppressions.location>${parent.pom.dir}/checkstyle-suppressions.xml
        </checkstyle.suppressions.location>

        <dependency.locations.enabled>false</dependency.locations.enabled>
    </properties>

    <!-- Dependency settings -->
    <dependencyManagement>
        <dependencies>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,10 +79,10 @@
         <!-- dependency versions -->
         <version.antlr4>4.8-1</version.antlr4>
         <version.logback>1.2.3</version.logback>
-        <version.jetty>9.4.26.v20200117</version.jetty>
+        <version.jetty>9.4.27.v20200227</version.jetty>
         <version.restassured>4.2.0</version.restassured>
         <version.jackson>2.10.3</version.jackson>
-        <version.jersey>2.30</version.jersey>
+        <version.jersey>2.30.1</version.jersey>
         <version.junit>5.6.0</version.junit>
         <hibernate3.version>3.6.10.Final</hibernate3.version>
         <version.mysql>8.0.19</version.mysql>
```
