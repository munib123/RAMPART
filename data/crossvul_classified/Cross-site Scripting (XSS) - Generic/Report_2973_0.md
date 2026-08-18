# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2973_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2973_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 105-145 of the vulnerable file.

{
    if ($code_before) {
        preg_match_all('#<prebtcode( data-language="\w+")?></prebtcode>#s', $texte, $code_after, PREG_SET_ORDER);
        foreach ($code_before as $i => $code) {
            $pos = strpos($texte, $code_after[$i][0]);
            if ($pos !== false) {
                 $texte = substr_replace($texte, '<pre'.((isset($code_after[$i][1])) ? $code_after[$i][1] : '').'><code>'.htmlspecialchars(htmlspecialchars_decode($code_before[$i][3])).'</code></pre>', $pos, strlen($code_after[$i][0]));
            }
        }
    }
    return $texte;
}

/**
 * used by markup()
 * convert a BBCode link to HTML <a>
 * with a check on URL
 *
 * @params array $matches, array from preg_replace_callback
 * @return string
 */
function markup_clean_href($matches)
{
    // var_dump($matches);
    $allowed = array('http://', 'https://', 'ftp://');
    // if not a valid url, return the string
    if ((
            !filter_var($matches['2'], FILTER_VALIDATE_URL)
         || !preg_match('#^('.join('|', $allowed).')#i', $matches['2'])
        )
     && !preg_match('/^#[\w-_]+$/i', $matches['2']) // allowing [text|#look-at_this]
    ) {
        return $matches['0'];
    }
    // handle different case
    if (empty(trim($matches['1']))) {
        return $matches['1'].'<a href="'.$matches['2'].'">'.$matches['2'].'</a>';
    } else {
        return '<a href="'.$matches['2'].'">'.$matches['1'].'</a>';
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,16 +122,21 @@
  *
  * @params array $matches, array from preg_replace_callback
  * @return string
+ *
+ * dirty fix, to do : review the htmlspecialchars policy before this function
  */
 function markup_clean_href($matches)
 {
-    // var_dump($matches);
     $allowed = array('http://', 'https://', 'ftp://');
+
+    // remove the filter, currentlty doesn't work without working/reformating the submitted url, idn & others stuff...
+    // !filter_var($matches['2'], FILTER_VALIDATE_URL) || 
+
+    // encode < > ", ' allowed in url
+    $matches['2'] = htmlspecialchars(htmlspecialchars_decode($matches['2']), ENT_COMPAT);
+
     // if not a valid url, return the string
-    if ((
-            !filter_var($matches['2'], FILTER_VALIDATE_URL)
-         || !preg_match('#^('.join('|', $allowed).')#i', $matches['2'])
-        )
+    if (!preg_match('#^('.join('|', $allowed).')#i', $matches['2'])
      && !preg_match('/^#[\w-_]+$/i', $matches['2']) // allowing [text|#look-at_this]
     ) {
         return $matches['0'];
```
