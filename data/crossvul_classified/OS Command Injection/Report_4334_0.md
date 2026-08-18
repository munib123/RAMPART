# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in html
**Pair ID:** 4334_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4334_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```html
Lines 10-50 of the vulnerable file.

 
 Created on 29. January 2005 by Joe Walnes
 -->
<head>
<title>Change History</title>
</head>
<body>

	<p>Changes are split into three categories:</p>

	<ul>
		<li><b>Major changes</b>: The major new features that all users should know about.</li>
		<li><b>Minor changes</b>: Any smaller changes, including bugfixes.</li>
		<li><b>API changes</b>: Any changes to the API that could impact existing users.</li>
	</ul>

	<p>
		Full details can be found in GitHub's <a href="https://github.com/x-stream/xstream/issues?q=is%3Aissue+is%3Aclosed">Issues</a>,
		filter for the appropriate milestone.
	</p>

	<h1 id="1.4.13">1.4.13</h1>

	<p>Released September 6, 2020.</p>

	<h2>Major changes</h2>

	<ul>
		<li>GHPR:#218: Defer reflective access to Java core modules.</li>
		<li>GHI:#207: New predefined blacklist avoids vulnerability due to improper setup of the security framework.</li>
	</ul>

	<h1 id="1.4.12">1.4.12</h1>

	<p>Released April 12, 2020.</p>

	<h2>Minor changes</h2>

	<ul>
		<li>XmlFriendlyNameCoder supports now XML parsers implementing only 4th edition of XML 1.0 specification.</li>
		<li>Fix support of CDATA events in StAX.</li>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,14 @@
 		Full details can be found in GitHub's <a href="https://github.com/x-stream/xstream/issues?q=is%3Aissue+is%3Aclosed">Issues</a>,
 		filter for the appropriate milestone.
 	</p>
+
+	<h1 id="upcoming-1.4.x">Upcoming 1.4.x maintenance release</h1>
+
+	<p>Not yet released.</p>
+
+	<p class="highlight">This maintenance release addresses the security vulnerability CVE-2017-9805 reported
+	originally for Struts' XStream Plugin, an arbitrary execution of commands when unmarshalling for XStream instances
+	with uninitialized security framework.</p>
 
 	<h1 id="1.4.13">1.4.13</h1>
 
```
