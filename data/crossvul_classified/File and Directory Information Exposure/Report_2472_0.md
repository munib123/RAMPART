# CrossVul Fix Pair: Files or Directories Accessible to External Parties in xml
**Pair ID:** 2472_0
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2472_0`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```xml
Lines 46-86 of the vulnerable file.

    <modules>
        <module>elide-swagger</module>
        <module>elide-test-helpers</module>
    </modules>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.yahoo.elide</groupId>
                <artifactId>elide-core</artifactId>
                <version>4.5.14-SNAPSHOT</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <build>
        <pluginManagement>
            <plugins>
                <plugin>
                    <groupId>org.codehaus.mojo</groupId>
                    <artifactId>build-helper-maven-plugin</artifactId>
                    <version>3.0.0</version>
                    <executions>
                        <execution>
                            <id>add-source-generate-sources</id>
                            <phase>generate-sources</phase>
                            <goals>
                                <goal>add-source</goal>
                            </goals>
                            <configuration>
                                <sources>
                                    <source>target/generated-sources/antlr4</source>
                                </sources>
                            </configuration>
                        </execution>
                        <execution>
                            <id>reserve-network-port-process-test-classes</id>
                            <phase>process-test-classes</phase>
                            <goals>
                                <goal>reserve-network-port</goal>
                            </goals>
                            <configuration>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,7 +63,7 @@
                 <plugin>
                     <groupId>org.codehaus.mojo</groupId>
                     <artifactId>build-helper-maven-plugin</artifactId>
-                    <version>3.0.0</version>
+                    <version>3.1.0</version>
                     <executions>
                         <execution>
                             <id>add-source-generate-sources</id>
```
