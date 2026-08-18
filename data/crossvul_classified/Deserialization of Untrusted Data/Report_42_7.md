# CrossVul Fix Pair: Deserialization of Untrusted Data in html
**Pair ID:** 42_7
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `42_7`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```html
Lines 11-51 of the vulnerable file.

<pre>
</pre>
</font>
</center>
<h2>1.0 Introduction</h2>
<p>
The Bouncy Castle Crypto package is a Java implementation of 
cryptographic algorithms.  The package is organised so that it 
contains a light-weight API suitable for use in any environment
(including the J2ME) with the additional infrastructure
to conform the algorithms to the JCE framework.
</p>
<h2>2.0 Release History</h2>

<h3>2.1.1 Version</h3>
Release: 1.60<br/>
Date:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 2018
<h3>2.1.2 Defects Fixed</h3>
<ul>
<li>Base64/UrlBase64 would throw an exception on a zero length string. This has been fixed.</li>
</ul>
<h3>2.1.3 Additional Features and Functionality</h3>
<ul>
<li>TLS: Extended CBC padding is now optional (and disabled by default).</li>
<li>TLS: Now supports channel binding 'tls-server-end-point'.</li>
<li>TLS: InterruptedIOException (e.g. socket timeout) during app-data reads no longer fails connection; handshake is optionally resumable after IIOE using 'TlsProtocol.setResumableHandshake()'.</li>
<li>BCJSSE: Now supports system property 'jdk.tls.client.protocols'</li>
<li>BCJSSE: Now supports SSLParameters.setSNIMatchers.</li>
<li>BCJSSE: SNI can now be used in earlier JDKs via BC extensions.</li>
<li>BCJSSE: Session context now holds sessions via soft references.</li>
</ul>
<h3>2.2.1 Version</h3>
Release: 1.59 <br/>
Date:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 2017, December 28
<h3>2.2.2 Defects Fixed</h3>
<ul>
<li>Issues with using PQC based keys with the provided BC KeyStores have now been fixed.</li>
<li>ECGOST-2012 public keys were being encoded with the wrong OID for the digest parameter in the algorithm parameter set. This has been fixed.</li>
<li>SM3 has now been added as an acceptable algorithm for TSP timestamps.</li>
<li>SM2 signatures were using the wrong default identity value. This has now been fixed.</li>
<li>An edge condition in Blake2b for hashes on data with a length in the range of 2**64 - 127 to 2**64 has been identifed and fixed.</li>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,7 @@
 <h3>2.1.2 Defects Fixed</h3>
 <ul>
 <li>Base64/UrlBase64 would throw an exception on a zero length string. This has been fixed.</li>
+<li>XMSS applies further validation to deserialisation of the BDS tree so that failure occurs as soon as tampering is detected.</li>
 </ul>
 <h3>2.1.3 Additional Features and Functionality</h3>
 <ul>
```
