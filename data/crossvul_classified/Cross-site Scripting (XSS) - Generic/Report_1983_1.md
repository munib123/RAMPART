# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1983_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1983_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 382-422 of the vulnerable file.

        $evilexpr = 'expression|behavior|javascript:|import[^a]' . (!$allow_remote ? '|url\((?!data:image)' : '');

        if (preg_match("/$evilexpr/i", $stripped)) {
            return '/* evil! */';
        }

        $strict_url_regexp = '!url\s*\(\s*["\']?(https?:)//[a-z0-9/._+-]+["\']?\s*\)!Uims';

        // cut out all contents between { and }
        while (($pos = strpos($source, '{', $last_pos)) && ($pos2 = strpos($source, '}', $pos))) {
            $nested = strpos($source, '{', $pos+1);
            if ($nested && $nested < $pos2)  // when dealing with nested blocks (e.g. @media), take the inner one
                $pos = $nested;
            $length = $pos2 - $pos - 1;
            $styles = substr($source, $pos+1, $length);

            // Convert position:fixed to position:absolute (#5264)
            $styles = preg_replace('/position[^a-z]*:[\s\r\n]*fixed/i', 'position: absolute', $styles);

            // Remove 'page' attributes (#7604)
            $styles = preg_replace('/(^|[\n\s;])page:[^;]+;*/im', '', $styles);

            // check every line of a style block...
            if ($allow_remote) {
                $a_styles = preg_split('/;[\r\n]*/', $styles, -1, PREG_SPLIT_NO_EMPTY);

                for ($i=0, $len=count($a_styles); $i < $len; $i++) {
                    $line     = $a_styles[$i];
                    $stripped = preg_replace('/[^a-z\(:;]/i', '', $line);

                    // allow data:image uri, join with continuation
                    if (stripos($stripped, 'url(data:image')) {
                        $a_styles[$i] .= ';' . $a_styles[$i+1];
                        unset($a_styles[$i+1]);
                    }
                    // allow strict url() values only
                    else if (stripos($stripped, 'url(') && !preg_match($strict_url_regexp, $line)) {
                        $a_styles = array('/* evil! */');
                        break;
                    }
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -399,7 +399,7 @@
             $styles = preg_replace('/position[^a-z]*:[\s\r\n]*fixed/i', 'position: absolute', $styles);
 
             // Remove 'page' attributes (#7604)
-            $styles = preg_replace('/(^|[\n\s;])page:[^;]+;*/im', '', $styles);
+            $styles = preg_replace('/((^|[\n\s;])page:)[^;]+;*/im', '\\1 unset;', $styles);
 
             // check every line of a style block...
             if ($allow_remote) {
```
