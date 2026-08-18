# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in xml
**Pair ID:** 3279_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3279_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```xml
Lines 124-183 of the vulnerable file.

      <groupId>org.jbpm</groupId>
      <artifactId>jbpm-flow</artifactId>
    </dependency>
    <dependency>
      <groupId>org.jbpm</groupId>
      <artifactId>jbpm-flow-builder</artifactId>
    </dependency>
    <dependency>
      <groupId>org.jbpm</groupId>
      <artifactId>jbpm-workitems</artifactId>
      <exclusions>
        <exclusion>
          <groupId>jdom</groupId>
          <artifactId>jdom</artifactId>
        </exclusion>
      </exclusions>
    </dependency>
    <dependency>
      <groupId>org.jbpm</groupId>
      <artifactId>jbpm-bpmn2-emfextmodel</artifactId>
    </dependency>

    <!-- jBPM Migration -->
    <dependency>
      <groupId>org.jbpm.jbpm5</groupId>
      <artifactId>jbpmmigration</artifactId>
      <exclusions>
        <exclusion>
          <groupId>log4j</groupId>
          <artifactId>log4j</artifactId>
        </exclusion>
        <exclusion>
          <groupId>xml-apis</groupId>
          <artifactId>xml-apis</artifactId>
        </exclusion>
        <exclusion>
          <groupId>xalan</groupId>
          <artifactId>xalan</artifactId>
        </exclusion>
        <exclusion>
          <groupId>xerces</groupId>
          <artifactId>xercesImpl</artifactId>
        </exclusion>
      </exclusions>
    </dependency>

    <!--  Drools -->
    <dependency>
      <groupId>org.drools</groupId>
      <artifactId>drools-core</artifactId>
    </dependency>
    <dependency>
      <groupId>org.drools</groupId>
      <artifactId>drools-compiler</artifactId>
    </dependency>

    <!-- Form Modeler -->
    <dependency>
      <groupId>org.jbpm</groupId>
      <artifactId>jbpm-form-modeler-bpmn-form-builder</artifactId>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,30 +141,6 @@
     <dependency>
       <groupId>org.jbpm</groupId>
       <artifactId>jbpm-bpmn2-emfextmodel</artifactId>
-    </dependency>
-
-    <!-- jBPM Migration -->
-    <dependency>
-      <groupId>org.jbpm.jbpm5</groupId>
-      <artifactId>jbpmmigration</artifactId>
-      <exclusions>
-        <exclusion>
-          <groupId>log4j</groupId>
-          <artifactId>log4j</artifactId>
-        </exclusion>
-        <exclusion>
-          <groupId>xml-apis</groupId>
-          <artifactId>xml-apis</artifactId>
-        </exclusion>
-        <exclusion>
-          <groupId>xalan</groupId>
-          <artifactId>xalan</artifactId>
-        </exclusion>
-        <exclusion>
-          <groupId>xerces</groupId>
-          <artifactId>xercesImpl</artifactId>
-        </exclusion>
-      </exclusions>
     </dependency>
 
     <!--  Drools -->
```
