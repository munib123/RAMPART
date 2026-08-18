# CrossVul Fix Pair: Files or Directories Accessible to External Parties in xml
**Pair ID:** 2472_1
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2472_1`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```xml
Lines 90-130 of the vulnerable file.

            <artifactId>logback-core</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-engine</artifactId>
        </dependency>

    </dependencies>
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
@@ -107,7 +107,7 @@
                 <plugin>
                     <groupId>org.codehaus.mojo</groupId>
                     <artifactId>build-helper-maven-plugin</artifactId>
-                    <version>3.0.0</version>
+                    <version>3.1.0</version>
                     <executions>
                         <execution>
                             <id>add-source-generate-sources</id>
```
