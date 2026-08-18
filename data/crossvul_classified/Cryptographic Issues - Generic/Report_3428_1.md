# CrossVul Fix Pair: Cryptographic Issues in xml
**Pair ID:** 3428_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3428_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```xml
Lines 1-27 of the vulnerable file.

<?xml version="1.0" encoding="latin1" ?>
<!DOCTYPE erlref SYSTEM "erlref.dtd">

<erlref>
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

    <title>crypto</title>
    <prepared>Peter H&ouml;gfeldt</prepared>
    <docno></docno>
    <date>2000-06-20</date>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 <erlref>
   <header>
     <copyright>
-      <year>1999</year><year>2010</year>
+      <year>1999</year><year>2011</year>
       <holder>Ericsson AB. All Rights Reserved.</holder>
     </copyright>
     <legalnotice>
@@ -619,6 +619,21 @@
       </desc>
     </func>
     <func>
+      <name>strong_rand_bytes(N) -> binary()</name>
+      <fsummary>Generate a binary of random bytes</fsummary>
+      <type>
+        <v>N = integer()</v>
+      </type>
+      <desc>
+        <p>Generates N bytes randomly uniform 0..255, and returns the
+        result in a binary. Uses a cryptographically secure prng seeded and
+        periodically mixed with operating system provided entropy. By default
+        this is the <c>RAND_bytes</c> method from OpenSSL.</p>
+	<p>May throw exception <c>low_entropy</c> in case the random generator
+	failed due to lack of secure "randomness".</p>
+      </desc>
+    </func>
+    <func>
       <name>rand_uniform(Lo, Hi) -> N</name>
       <fsummary>Generate a random number</fsummary>
       <type>
@@ -630,6 +645,31 @@
           <c>crypto</c> library pseudo-random number generator. The
           arguments (and result) can be either erlang integers or binary
           multi-precision integers.</p>
+      </desc>
+    </func>
+    <func>
+      <name>strong_rand_mpint(N, Top, Bottom) -> Mpint</name>
+      <fsummary>Generate an N bit random number</fsummary>
+      <type>
+        <v>N = non_neg_integer()</v>
+        <v>Top = -1 | 0 | 1</v>
+        <v>Bottom = 0 | 1</v>
+        <v>Mpint = binary()</v>
+      </type>
+      <desc>
+        <p>Generate an N bit random number using OpenSSL's
+        cryptographically strong pseudo random number generator
+        <c>BN_rand</c>.</p>
+        <p>The parameter <c>Top</c> places constraints on the most
+        significant bits of the generated number. If <c>Top</c> is 1, then the
+        two most significant bits will be set to 1, if <c>Top</c> is 0, the
+        most significant bit will be 1, and if <c>Top</c> is -1 then no
+        constraints are applied and thus the generated number may be less than
+        N bits long.</p>
+        <p>If <c>Bottom</c> is 1, then the generated number is
+        constrained to be odd.</p>
+	<p>May throw exception <c>low_entropy</c> in case the random generator
+	failed due to lack of secure "randomness".</p>
       </desc>
     </func>
     <func>
```
