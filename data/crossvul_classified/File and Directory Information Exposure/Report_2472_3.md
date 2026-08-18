# CrossVul Fix Pair: Files or Directories Accessible to External Parties in xml
**Pair ID:** 2472_3
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2472_3`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```xml
Lines 31-71 of the vulnerable file.

        <name>Yahoo! Inc.</name>
        <url>http://www.yahoo.com</url>
    </organization>

    <developers>
        <developer>
            <name>Yahoo Inc.</name>
            <url>https://github.com/yahoo</url>
        </developer>
    </developers>

    <scm>
        <developerConnection>scm:git:ssh://git@github.com/yahoo/elide.git</developerConnection>
        <url>https://github.com/yahoo/elide.git</url>
        <tag>HEAD</tag>
    </scm>

    <properties>
        <!-- Versions -->
        <logback.version>1.2.3</logback.version>
        <metrics.version>4.1.2</metrics.version>

        <!-- Settings -->
        <project.build.sourceEncoding>utf-8</project.build.sourceEncoding>
        <min_jdk_version>1.8</min_jdk_version>
        <max_jdk_version>1.8</max_jdk_version>
    </properties>

    <dependencies>
        <!-- Elide dependency -->
        <dependency>
            <groupId>com.yahoo.elide</groupId>
            <artifactId>elide-datastore-jpa</artifactId>
            <version>4.5.14-SNAPSHOT</version>
        </dependency>
        <dependency>
            <groupId>com.yahoo.elide</groupId>
            <artifactId>elide-graphql</artifactId>
            <version>4.5.14-SNAPSHOT</version>
        </dependency>
        <dependency>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,7 +48,7 @@
     <properties>
         <!-- Versions -->
         <logback.version>1.2.3</logback.version>
-        <metrics.version>4.1.2</metrics.version>
+        <metrics.version>4.1.5</metrics.version>
 
         <!-- Settings -->
         <project.build.sourceEncoding>utf-8</project.build.sourceEncoding>
```
