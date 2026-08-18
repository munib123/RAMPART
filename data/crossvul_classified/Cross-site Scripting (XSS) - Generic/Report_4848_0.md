# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4848_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4848_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<script language="PHP">
require "search_functions.php";

$mode = array_key_exists('v', $_GET)?$_GET['v']:"";
$query = array_key_exists('query', $_GET)?$_GET['query']:"";

$query_results = run_query($query);

switch ($mode)
{
  case "opensearch.xml":
    opensearch_description();
    break;
  case "json":
    opensearch_json_results($query, $query_results);
    break;
  case "xml":
    opensearch_xml_results($query, $query_results);
    break;
  default:
    invalid_format($query, $query_results);
    break;
}

function opensearch_description()
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 
 $mode = array_key_exists('v', $_GET)?$_GET['v']:"";
 $query = array_key_exists('query', $_GET)?$_GET['query']:"";
+$query = preg_replace("/[^a-zA-Z0-9\-\_\.\x80-\xFF]/i", " ", $query );
 
 $query_results = run_query($query);
 
```
