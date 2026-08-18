# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in html
**Pair ID:** 3568_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3568_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```html
Lines 1-31 of the vulnerable file.

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <title>Raptor RDF Syntax Library - News</title>
</head>
<body>

<h1 style="text-align:center">Raptor RDF Syntax Library - News</h1>

<h2 id="D2012-XX-XX-V2.0.7">2012-XX-XX Raptor2 Version 2.0.7 Released</h2>

<p>Not yet released.
</p>

<p>
Removed Expat support<br />
Removed internal Unicode NFC code for better and optional <a href="http://www.icu-project.org/">ICU</a><br />
Added new options for denying file requests and SSL certificate verifying<br />
Fixed reported <a href="http://bugs.librdf.org/">issues</a>:
<a href="http://bugs.librdf.org/mantis/view.php?id=448">0000448</a> and
<a href="http://bugs.librdf.org/mantis/view.php?id=469">0000469</a>
</p>


<h2 id="D2011-11-27-V2.0.6">2011-11-27 Raptor2 Version 2.0.6 Released</h2>

<p>
Fixed expat support which was broken in 2.0.5<br />
Handle libCurl SSL options before 7.16.4 (2007)<br />
Add a few sequence utility methods for sort, reverse and permute<br />
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,19 +8,20 @@
 
 <h1 style="text-align:center">Raptor RDF Syntax Library - News</h1>
 
-<h2 id="D2012-XX-XX-V2.0.7">2012-XX-XX Raptor2 Version 2.0.7 Released</h2>
-
-<p>Not yet released.
-</p>
-
-<p>
+<h2 id="D2012-03-22-V2.0.7">2012-03-22 Raptor2 Version 2.0.7 Released</h2>
+
+<p>CVE-2012-0037 fixed<br />
 Removed Expat support<br />
 Removed internal Unicode NFC code for better and optional <a href="http://www.icu-project.org/">ICU</a><br />
-Added new options for denying file requests and SSL certificate verifying<br />
+Added options for denying file requests and XML entity loading<br />
+Added options for SSL certificate verifying<br />
 Fixed reported <a href="http://bugs.librdf.org/">issues</a>:
 <a href="http://bugs.librdf.org/mantis/view.php?id=448">0000448</a> and
 <a href="http://bugs.librdf.org/mantis/view.php?id=469">0000469</a>
 </p>
+
+<p>See the <a href="RELEASE.html#rel2_0_7">Raptor2 2.0.7 Release Notes</a>
+for the full details of the changes.</p>
 
 
 <h2 id="D2011-11-27-V2.0.6">2011-11-27 Raptor2 Version 2.0.6 Released</h2>
```
