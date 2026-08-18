# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1959_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1959_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 4383-4423 of the vulnerable file.

MAX_cookieAdd($conf['var']['vars'] . "[$n]", json_encode($cookie, JSON_UNESCAPED_SLASHES));
} else {
MAX_cookieUnset($conf['var']['vars'] . "[$n]");
}
}
MAX_cookieFlush();
MAX_commonSendContentTypeHeader('text/html', $charset);
if (isset($rewrite) && $rewrite == 1) {
$banner['html'] = preg_replace('#target\s*=\s*([\'"])_parent\1#i', "target='_top'", $banner['html']);
$banner['html'] = preg_replace('#target\s*=\s*([\'"])_self\1#i', "target='_parent'", $banner['html']);
}
$outputHtml = "<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>\n";
$outputHtml .= "<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en' lang='en'>\n";
$outputHtml .= "<head>\n";
$outputHtml .= "<title>".(!empty($banner['alt']) ? $banner['alt'] : 'Advertisement')."</title>\n";
if (isset($refresh) && is_numeric($refresh) && $refresh > 0) {
$dest = MAX_commonGetDeliveryUrl($conf['file']['frame']).'?'.$_SERVER['QUERY_STRING'];
parse_str($_SERVER['QUERY_STRING'], $qs);
$dest .= (!array_key_exists('loc', $qs)) ? "&loc=" . urlencode($loc) : '';
$refresh = (int)$refresh;
$jsDest = addcslashes(addcslashes($dest, "\0..\37\"\\"), "'\\");
$htmlDest = htmlspecialchars($dest, ENT_QUOTES);
$outputHtml .= "
    <script type='text/javascript'><!--// <![CDATA[
        setTimeout('window.location.replace(\"{$jsDest}\")', " . ($refresh * 1000) . ");
    // ]]> --></script><noscript><meta http-equiv='refresh' content='".$refresh.";url={$htmlDest}'></noscript>
    ";
}
if (isset($resize) && $resize == 1) {
$bannerWidth = empty($banner['width']) ? 0 : $banner['width'];
$bannerHeight = empty($banner['height']) ? 0 : $banner['height'];
$outputHtml .= "<script type='text/javascript'>\n";
$outputHtml .= "<!--// <![CDATA[ \n";
$outputHtml .= "\tfunction MAX_adjustframe(frame) {\n";
$outputHtml .= "\t\tif (document.all) {\n";
$outputHtml .= "\t\t\tparent.document.all[frame.name].width = ".$bannerWidth.";\n";
$outputHtml .= "\t\t\tparent.document.all[frame.name].height = ".$bannerHeight.";\n";
$outputHtml .= "\t\t}\n";
$outputHtml .= "\t\telse if (document.getElementById) {\n";
$outputHtml .= "\t\t\tparent.document.getElementById(frame.name).width = ".$bannerWidth.";\n";
$outputHtml .= "\t\t\tparent.document.getElementById(frame.name).height = ".$bannerHeight.";\n";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4400,7 +4400,7 @@
 parse_str($_SERVER['QUERY_STRING'], $qs);
 $dest .= (!array_key_exists('loc', $qs)) ? "&loc=" . urlencode($loc) : '';
 $refresh = (int)$refresh;
-$jsDest = addcslashes(addcslashes($dest, "\0..\37\"\\"), "'\\");
+$jsDest = addcslashes(addcslashes($dest, "\0..\37/\"\\"), "'\\");
 $htmlDest = htmlspecialchars($dest, ENT_QUOTES);
 $outputHtml .= "
     <script type='text/javascript'><!--// <![CDATA[
```
