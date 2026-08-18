# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 2055_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2055_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 1-27 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8"?>
<project name="easyXDM" default="build" basedir=".">
	<property file="build.properties"/>
	<property file="build.secret.properties"/>
	<property name="project.build.artifactdir" value="./artifacts/"/>
	<property name="project.build.publishdir" value="./artifacts/"/>
	<property name="project.build.version" value="2.4.18"/>
	
	<!-- Setup classpath for js-build-tools ant tasks -->
	<path id="js-build-tasks.classpath">
		<pathelement location="."/>
		<fileset dir="tools/js-build-tools/lib">
			<include name="**/*.jar"/>
		</fileset>
	</path>
	
	<taskdef name="preprocess" classname="com.moxiecode.ant.tasks.PreProcessTask" classpathref="js-build-tasks.classpath" loaderref="js-build-tasks.classpath.loader" />
	<taskdef name="yuicompress" classname="com.moxiecode.ant.tasks.YuiCompressTask" classpathref="js-build-tasks.classpath" loaderref="js-build-tasks.classpath.loader" />
	<taskdef name="jslint" classname="com.googlecode.jslint4java.ant.JSLintTask" classpath="tools/jslint4java-1.3.3/jslint4java-1.3.3.jar" />
	
	<path id="githubhuploadtask.classpath">
		<pathelement location="."/>
		<fileset dir="tools/GitHubUploadTask">
			<include name="**/*.jar"/>
		</fileset>
	</path>
	<taskdef name="upload" classname="no.kinsey.ant.GitHubUploadTask" classpathref="githubhuploadtask.classpath" loaderref="githubhuploadtask.classpath.loader" />
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 	<property file="build.secret.properties"/>
 	<property name="project.build.artifactdir" value="./artifacts/"/>
 	<property name="project.build.publishdir" value="./artifacts/"/>
-	<property name="project.build.version" value="2.4.18"/>
+	<property name="project.build.version" value="2.4.19"/>
 	
 	<!-- Setup classpath for js-build-tools ant tasks -->
 	<path id="js-build-tasks.classpath">
```
