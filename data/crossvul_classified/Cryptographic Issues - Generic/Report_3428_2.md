# CrossVul Fix Pair: Cryptographic Issues in xml
**Pair ID:** 3428_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3428_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```xml
Lines 1-27 of the vulnerable file.

<?xml version="1.0" encoding="latin1" ?>
<!DOCTYPE chapter SYSTEM "chapter.dtd">

<chapter>
  <header>
    <copyright>
      <year>1999</year><year>2010</year>
      <holder>Ericsson AB. All Rights Reserved.</holder>
    </copyright>
    <legalnotice>
      The contents of this file are subject to the Erlang Public License,
      Version 1.1, (the "License"); you may not use this file except in
      compliance with the License. You should have received a copy of the
      Erlang Public License along with this software. If not, it can be
      retrieved online at http://www.erlang.org/.

      Software distributed under the License is distributed on an "AS IS"
      basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
      the License for the specific language governing rights and limitations
      under the License.

    </legalnotice>

    <title>Crypto Release Notes</title>
    <prepared>Peter H&ouml;gfeldt</prepared>
    <docno></docno>
    <date>2003-06-06</date>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 <chapter>
   <header>
     <copyright>
-      <year>1999</year><year>2010</year>
+      <year>1999</year><year>2011</year>
       <holder>Ericsson AB. All Rights Reserved.</holder>
     </copyright>
     <legalnotice>
@@ -29,6 +29,21 @@
     <file>notes.xml</file>
   </header>
   <p>This document describes the changes made to the Crypto application.</p>
+
+<section><title>Crypto 2.0.2.2</title>
+
+    <section><title>Improvements and New Features</title>
+      <list>
+        <item>
+          <p>
+	    Strengthened random number generation. (Thanks to Geoff Cant)</p>
+          <p>
+	    Own Id: OTP-9225</p>
+        </item>
+      </list>
+    </section>
+
+</section>
 
 <section><title>Crypto 2.0.2.1</title>
 
```
