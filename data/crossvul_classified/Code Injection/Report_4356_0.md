# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in xml
**Pair ID:** 4356_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4356_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```xml
Lines 104-145 of the vulnerable file.

        </dependency>
        <dependency>
            <groupId>org.powermock</groupId>
            <artifactId>powermock-module-junit4</artifactId>
            <version>${powermock.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.powermock</groupId>
            <artifactId>powermock-api-mockito2</artifactId>
            <version>${powermock.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.quartz-scheduler</groupId>
            <artifactId>quartz</artifactId>
            <version>2.3.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.hibernate</groupId>
            <artifactId>hibernate-validator</artifactId>
            <!-- https://stackoverflow.com/questions/48323244/java-lang-nosuchmethoderror-javax-validation-bootstrapconfiguration-getclockproExecutionTimeQuartzIntegrationTest -->
            <!-- https://stackoverflow.com/questions/24386771/javax-validation-validationexception-hv000183-unable-to-load-javax-el-express -->
            <version>5.3.6.Final</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>javax.el</groupId>
            <artifactId>javax.el-api</artifactId>
            <version>3.0.0</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.glassfish</groupId>
            <artifactId>javax.el</artifactId>
            <version>3.0.0</version>
        </dependency>
        <dependency>
			<groupId>org.apache.commons</groupId>
			<artifactId>commons-lang3</artifactId>
			<version>3.11</version>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,11 +121,12 @@
             <scope>test</scope>
         </dependency>
         <dependency>
-            <groupId>org.hibernate</groupId>
-            <artifactId>hibernate-validator</artifactId>
+            <groupId>org.apache.bval</groupId>
+            <artifactId>bval-jsr</artifactId>
+            <version>1.1.2</version>
+            <!--The Hibernate dependency is no longer used, due to security vulnerabilities -->
             <!-- https://stackoverflow.com/questions/48323244/java-lang-nosuchmethoderror-javax-validation-bootstrapconfiguration-getclockproExecutionTimeQuartzIntegrationTest -->
             <!-- https://stackoverflow.com/questions/24386771/javax-validation-validationexception-hv000183-unable-to-load-javax-el-express -->
-            <version>5.3.6.Final</version>
             <scope>test</scope>
         </dependency>
         <dependency>
```
