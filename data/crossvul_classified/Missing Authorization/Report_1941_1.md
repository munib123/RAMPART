# CrossVul Fix Pair: Missing Authorization in xml
**Pair ID:** 1941_1
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1941_1`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```xml
Lines 1-24 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8"?>
<project default="core" basedir="." name="Lucee" xmlns:artifact="antlib:org.apache.maven.artifact.ant">

  <property name="version" value="5.3.8.88-SNAPSHOT"/>

  <path id="maven-ant-tasks.classpath" path="../ant/lib/maven-ant-tasks-2.1.3.jar" />
  <typedef resource="org/apache/maven/artifact/ant/antlib.xml"
           uri="antlib:org.apache.maven.artifact.ant"
           classpathref="maven-ant-tasks.classpath" />

  <import file="../ant/build-core.xml"/>


  <target name="withTestcases">
    <property name="testcases" value="true"/>
  </target>

  <target name="setEnv">
      <artifact:pom id="pom" file="pom.xml" />

      <!-- dependecies -->
      <artifact:dependencies filesetId="mydeps" pomRefId="pom" />
      <pathconvert property="dependencies" refid="mydeps"/>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <project default="core" basedir="." name="Lucee" xmlns:artifact="antlib:org.apache.maven.artifact.ant">
 
-  <property name="version" value="5.3.8.88-SNAPSHOT"/>
+  <property name="version" value="5.3.8.89-SNAPSHOT"/>
 
   <path id="maven-ant-tasks.classpath" path="../ant/lib/maven-ant-tasks-2.1.3.jar" />
   <typedef resource="org/apache/maven/artifact/ant/antlib.xml"
```
