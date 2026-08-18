# CrossVul Fix Pair: Improper Authentication in xml
**Pair ID:** 2029_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2029_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```xml
Lines 10-50 of the vulnerable file.

  <groupId>io.hawt</groupId>
  <artifactId>hawtio-karaf-terminal</artifactId>
  <description>hawtio :: Karaf terminal plugin</description>
  <name>${project.artifactId}</name>

  <packaging>war</packaging>

  <properties>
    <!-- filtered plugin properties -->
    <plugin-context>/hawtio/hawtio-karaf-terminal</plugin-context>
    <plugin-name>${project.artifactId}</plugin-name>
    <plugin-domain />
    <plugin-scripts>app/js/gogoPlugin.js,app/js/gogo.js</plugin-scripts>
  </properties>

  <dependencies>

    <dependency>
      <groupId>io.hawt</groupId>
      <artifactId>hawtio-plugin-mbean</artifactId>
      <version>${project.version}</version>
    </dependency>

    <dependency>
      <groupId>javax.servlet</groupId>
      <artifactId>servlet-api</artifactId>
      <version>${servlet-api-version}</version>
      <scope>provided</scope>
    </dependency>

    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j-version}</version>
      <scope>provided</scope>
    </dependency>

    <dependency>
      <groupId>org.apache.felix</groupId>
      <artifactId>org.apache.felix.gogo.runtime</artifactId>
      <version>${felix.gogo.version}</version>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,12 @@
     <dependency>
       <groupId>io.hawt</groupId>
       <artifactId>hawtio-plugin-mbean</artifactId>
+      <version>${project.version}</version>
+    </dependency>
+
+    <dependency>
+      <groupId>io.hawt</groupId>
+      <artifactId>hawtio-system</artifactId>
       <version>${project.version}</version>
     </dependency>
 
```
