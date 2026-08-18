# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in xml
**Pair ID:** 4347_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4347_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```xml
Lines 11-51 of the vulnerable file.

<project xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xmlns="http://maven.apache.org/POM/4.0.0"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.dpppt</groupId>
        <artifactId>dpppt-backend-sdk</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </parent>
    <artifactId>dpppt-backend-sdk-ws</artifactId>
    <name>DP3T Backend SDK WS</name>
    <packaging>jar</packaging>

    <properties>
        <start-class>org.dpppt.backend.sdk.ws.Application</start-class>
        <sonar.projectKey>DP-3T_dp3t-sdk-backend</sonar.projectKey>
    </properties>

    <profiles>
        <profile>
            <id>radarcovid-local</id>
            <properties>
                <build.profile.id>radarcovid-local</build.profile.id>
            </properties>
        </profile>
		<profile>
            <id>radarcovid-pre</id>
            <properties>
                <build.profile.id>radarcovid-pre</build.profile.id>
            </properties>
        </profile>
        <profile>
            <id>radarcovid-pro</id>
            <properties>
                <build.profile.id>radarcovid-pro</build.profile.id>
            </properties>
        </profile>
    </profiles>

    <dependencies>
        <dependency>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,23 @@
 
     <profiles>
         <profile>
+            <id>aws-metrics</id>
+            <dependencies>
+                <dependency>
+                    <groupId>org.springframework.cloud</groupId>
+                    <artifactId>spring-cloud-starter-aws</artifactId>
+                </dependency>
+                <dependency>
+                    <groupId>org.springframework.cloud</groupId>
+                    <artifactId>spring-cloud-aws-actuator</artifactId>
+                </dependency>
+                <dependency>
+                    <groupId>io.micrometer</groupId>
+                    <artifactId>micrometer-registry-cloudwatch2</artifactId>
+                </dependency>
+            </dependencies>
+        </profile>
+        <profile>
             <id>radarcovid-local</id>
             <properties>
                 <build.profile.id>radarcovid-local</build.profile.id>
@@ -38,12 +55,24 @@
             <properties>
                 <build.profile.id>radarcovid-pre</build.profile.id>
             </properties>
+            <dependencies>
+                <dependency>
+                    <groupId>org.springframework.cloud</groupId>
+                    <artifactId>spring-cloud-starter-aws-parameter-store-config</artifactId>
+                </dependency>
+            </dependencies>
         </profile>
         <profile>
             <id>radarcovid-pro</id>
             <properties>
                 <build.profile.id>radarcovid-pro</build.profile.id>
             </properties>
+            <dependencies>
+                <dependency>
+                    <groupId>org.springframework.cloud</groupId>
+                    <artifactId>spring-cloud-starter-aws-parameter-store-config</artifactId>
+                </dependency>
+            </dependencies>
         </profile>
     </profiles>
 
@@ -60,10 +89,6 @@
 		<dependency>
 			<groupId>org.springframework.boot</groupId>
 			<artifactId>spring-boot-starter-cloud-connectors</artifactId>
-		</dependency>
-		<dependency>
-			<groupId>org.springframework.cloud</groupId>
-			<artifactId>spring-cloud-starter-aws-parameter-store-config</artifactId>
 		</dependency>
         <dependency>
             <groupId>org.springframework.security</groupId>
```
