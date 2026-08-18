# CrossVul Fix Pair: Files or Directories Accessible to External Parties in xml
**Pair ID:** 2472_2
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2472_2`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```xml
Lines 23-63 of the vulnerable file.

            <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
            <distribution>repo</distribution>
        </license>
    </licenses>

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
        <parent.pom.dir>${project.basedir}/../..</parent.pom.dir>
        <version.log4j>2.13.0</version.log4j>
    </properties>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.yahoo.elide</groupId>
                <artifactId>elide-core</artifactId>
                <version>4.5.14-SNAPSHOT</version>
            </dependency>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-slf4j-impl</artifactId>
                <version>${version.log4j}</version>
            </dependency>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-core</artifactId>
                <version>${version.log4j}</version>
            </dependency>
        </dependencies>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,7 +40,7 @@
 
     <properties>
         <parent.pom.dir>${project.basedir}/../..</parent.pom.dir>
-        <version.log4j>2.13.0</version.log4j>
+        <version.log4j>2.13.1</version.log4j>
     </properties>
 
     <dependencyManagement>
```
