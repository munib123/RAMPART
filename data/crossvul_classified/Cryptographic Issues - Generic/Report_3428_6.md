# CrossVul Fix Pair: Cryptographic Issues in xml
**Pair ID:** 3428_6
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3428_6`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```xml
Lines 11-51 of the vulnerable file.

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

    <title>SSH Release Notes</title>
    <prepared></prepared>
    <docno></docno>
    <date></date>
    <rev>%VSN%</rev>
    <file>notes.xml</file>
  </header>

<section><title>Ssh 2.0.4</title>
    <section><title>Fixed Bugs and Malfunctions</title>
      <list>
        <item>
          <p>In some cases SSH returned {error, normal} when a channel was terminated
             unexpectedly. This has now been changed to {error, channel_closed}.</p>
          <p>
            *** POTENTIAL INCOMPATIBILITY ***</p>
          <p>
            Own Id: OTP-8987 Aux Id: seq11748</p>
        </item>
        <item>
          <p>
            SSH did not handle the error reason enetunreach
            when trying to open a IPv6 connection.</p>
          <p>
            Own Id: OTP-9031</p>
        </item>
      </list>
    </section>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,19 @@
     <file>notes.xml</file>
   </header>
 
+<section><title>Ssh 2.0.5</title>
+    <section><title>Improvements and New Features</title>
+      <list>
+        <item>
+          <p>
+            Strengthened random number generation. (Thanks to Geoff Cant)</p>
+          <p>
+            Own Id: OTP-9225</p>
+        </item>
+      </list>
+    </section>
+</section>
+
 <section><title>Ssh 2.0.4</title>
     <section><title>Fixed Bugs and Malfunctions</title>
       <list>
```
