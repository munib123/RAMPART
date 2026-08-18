# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1958_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1958_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 60-100 of the vulnerable file.

// local to the parent and not local to the iframe
if (isset($rewrite) && $rewrite == 1) {
	$banner['html'] = preg_replace('#target\s*=\s*([\'"])_parent\1#i', "target='_top'", $banner['html']);
	$banner['html'] = preg_replace('#target\s*=\s*([\'"])_self\1#i', "target='_parent'", $banner['html']);
}

// Build HTML
$outputHtml = "<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>\n";
$outputHtml .= "<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en' lang='en'>\n";
$outputHtml .= "<head>\n";
$outputHtml .= "<title>".(!empty($banner['alt']) ? $banner['alt'] : 'Advertisement')."</title>\n";

// Add refresh meta tag if $refresh is set and numeric
if (isset($refresh) && is_numeric($refresh) && $refresh > 0) {
    $dest = MAX_commonGetDeliveryUrl($conf['file']['frame']).'?'.$_SERVER['QUERY_STRING'];
    parse_str($_SERVER['QUERY_STRING'], $qs);
    $dest .= (!array_key_exists('loc', $qs)) ? "&loc=" . urlencode($loc) : '';

    $refresh = (int)$refresh;
    // JS needs to be escaped twice: the setTimeout argument is evaluated at runtime
    $jsDest = addcslashes(addcslashes($dest, "\0..\37\"\\"), "'\\");
    $htmlDest = htmlspecialchars($dest, ENT_QUOTES);

    // Try to use JS location.replace since browsers deal with this and history much better than meta-refresh
	$outputHtml .= "
    <script type='text/javascript'><!--// <![CDATA[
        setTimeout('window.location.replace(\"{$jsDest}\")', " . ($refresh * 1000) . ");
    // ]]> --></script><noscript><meta http-equiv='refresh' content='".$refresh.";url={$htmlDest}'></noscript>
    ";
}

if (isset($resize) && $resize == 1) {
	// If no banner found, use 0 as width and height
	$bannerWidth = empty($banner['width']) ? 0 : $banner['width'];
	$bannerHeight = empty($banner['height']) ? 0 : $banner['height'];

	$outputHtml .= "<script type='text/javascript'>\n";
	$outputHtml .= "<!--// <![CDATA[ \n";
	$outputHtml .= "\tfunction MAX_adjustframe(frame) {\n";
	$outputHtml .= "\t\tif (document.all) {\n";
	$outputHtml .= "\t\t\tparent.document.all[frame.name].width = ".$bannerWidth.";\n";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,7 +77,7 @@
 
     $refresh = (int)$refresh;
     // JS needs to be escaped twice: the setTimeout argument is evaluated at runtime
-    $jsDest = addcslashes(addcslashes($dest, "\0..\37\"\\"), "'\\");
+    $jsDest = addcslashes(addcslashes($dest, "\0..\37/\"\\"), "'\\");
     $htmlDest = htmlspecialchars($dest, ENT_QUOTES);
 
     // Try to use JS location.replace since browsers deal with this and history much better than meta-refresh
```
