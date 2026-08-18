# CrossVul Fix Pair: Deserialization of Untrusted Data in xml
**Pair ID:** 3054_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3054_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```xml
Lines 162-202 of the vulnerable file.

      <dependency>
        <groupId>org.powermock</groupId>
        <artifactId>powermock-module-junit4</artifactId>
        <version>1.5.6</version>
      </dependency>
      <dependency>
        <groupId>org.powermock</groupId>
        <artifactId>powermock-api-mockito</artifactId>
        <version>1.5.6</version>
      </dependency>

      <dependency>
        <groupId>commons-httpclient</groupId>
        <artifactId>commons-httpclient</artifactId>
        <version>3.1</version>
      </dependency>

      <dependency>
        <groupId>org.jenkins-ci.main</groupId>
        <artifactId>remoting</artifactId>
        <version>2.53.4</version>
      </dependency>

      <dependency>
        <groupId>com.google.guava</groupId>
        <artifactId>guava</artifactId>
        <version>11.0.1</version>
      </dependency>

      <dependency>
        <groupId>com.google.inject</groupId>
        <artifactId>guice</artifactId>
        <version>4.0-beta</version>
      </dependency>

      <!-- SLF4J used in maven-plugin and core -->
      <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>${slf4jVersion}</version>
      </dependency>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -179,7 +179,7 @@
       <dependency>
         <groupId>org.jenkins-ci.main</groupId>
         <artifactId>remoting</artifactId>
-        <version>2.53.4</version>
+        <version>2.53.5-20170111.201445-1</version>
       </dependency>
 
       <dependency>
```
