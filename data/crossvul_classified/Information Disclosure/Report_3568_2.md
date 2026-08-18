# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in html
**Pair ID:** 3568_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3568_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```html
Lines 1-35 of the vulnerable file.

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
  <title>Raptor RDF Syntax Library - Release Notes</title>
</head>
<body>

<h1 style="text-align:center">Raptor RDF Syntax Library - Release Notes</h1>


<h2 id="rel2_0_7"><a name="rel2_0_7">Raptor2 2.0.7 changes</a></h2>

<p>Not yet released.
</p>

<p>Issues Fixed:</p>
<ul>
  <li><a href="http://bugs.librdf.org/mantis/view.php?id=448">0000448</a>: Turtle parser does not return error status from turtle_parse_chunk()</li>
  <li><a href="http://bugs.librdf.org/mantis/view.php?id=469">0000469</a>: Allow rapper to bypass server SSL certs checks in libcurl</li>
</ul>

<p>Removed Expat support since expat has not had a release in years
and libxml2 works well.  This allows some code simplification.
Updated <code>configure</code> so that if Raptor is configured with
no parser that requires an XML parser, libxml2 will not be required.
</p>

<p>Removed internal Unicode NFC checking code used for checking
RDF/XML literals conformance which was expensive to check and a large
of compiled-in static dataset that was rather out of date.  Replaced
with optional compiled use of <a href="http://www.icu-project.org/">ICU</a>.
If ICU is not explicitly configured, no literal checking is done.</p>

<h3>Options changes</h3>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,8 +11,7 @@
 
 <h2 id="rel2_0_7"><a name="rel2_0_7">Raptor2 2.0.7 changes</a></h2>
 
-<p>Not yet released.
-</p>
+<p>CVE-2012-0037 fixed</p>
 
 <p>Issues Fixed:</p>
 <ul>
@@ -39,6 +38,10 @@
   <dt><code>RAPTOR_OPTION_NO_FILE</code><br/></dt>
   <dd>Deny file requests during parsing.</dd>
 
+  <dt><code>RAPTOR_OPTION_LOAD_EXTERNAL_ENTITIES</code><br/></dt>
+  <dd>Deny loading of XML external entity loading. Disabled by
+  default.</dd>
+
   <dt><code>RAPTOR_OPTION_WWW_SSL_VERIFY_PEER</code><br/></dt>
   <dd>Controls verifying an SSL peer during parsing / WWW.  Takes an
   integer value: non-0 to verify peer SSL certificate (default
@@ -53,6 +56,10 @@
 
 <h3>Parser class changes</h3>
 
+<p>The RDF/XML, RSS Tag Soup and RDFa parsers now pass on network,
+file and entity loading parser options to the internal SAX2 to enable
+enforcing of network, file and entity loading policy.</p>
+
 <p>RDF/JSON parser handles an API change between YAJL V1 and V2.
 </p>
 
@@ -64,11 +71,18 @@
 
 <h3>SAX2 class changes</h3>
 
-<p>
-Added <code>raptor_sax2_set_uri_filter()</code> to set a URI filter
-for any SAX2 calls that do internal lookups of URIs.
-</p>
-
+<p>Added <code>raptor_sax2_set_uri_filter()</code> to set a URI
+filter for any SAX2 calls that do internal lookups of URIs.
+</p>
+
+<p>Control file and network loading inside SAX2.  Option
+<code>RAPTOR_OPTION_LOAD_EXTERNAL_ENTITIES</code> now enforces
+loading external XML entities and is by default enabled.  If enabled,
+<code>RAPTOR_OPTION_NO_FILE</code> and
+<code>RAPTOR_OPTION_NO_NET</code> are also checked.  All URIs loaded
+are also passed through any URI filter, if set by
+<code>raptor_sax2_set_uri_filter()</code>.
+</p>
 
 <h3>URI class changes</h3>
 
```
