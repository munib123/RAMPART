# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2826_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2826_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 99-139 of the vulnerable file.

}

/**
 *
 */
function parse_texte_code($texte, $code_before)
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
 *
 */
function markup($texte)
{
    $texte = preg_replace('#\[([^|]+)\|(\s*javascript.*)\]#i', '$1', $texte);
    $texte = preg_replace("/(\r\n|\r\n\r|\n|\n\r|\r)/", "\r", $texte);
    $tofind = array(
        /* regex URL     */ '#([^"\[\]|])((http|ftp)s?://([^"\'\[\]<>\s\)\(]+))#i',
        /* a href        */ '#\[([^[]+)\|([^[]+)\]#',
        /* strong        */ '#\[b\](.*?)\[/b\]#s',
        /* italic        */ '#\[i\](.*?)\[/i\]#s',
        /* strike        */ '#\[s\](.*?)\[/s\]#s',
        /* underline     */ '#\[u\](.*?)\[/u\]#s',
        /* quote         */ '#\[quote\](.*?)\[/quote\]#s',
        /* code          */ '#\[code\]\[/code\]#s',
        /* code=language */ '#\[code=(\w+)\]\[/code\]#s',
    );
    $toreplace = array(
        /* regex URL     */ '$1<a href="$2">$2</a>',
        /* a href        */ '<a href="$2">$1</a>',
        /* strong        */ '<b>$1</b>',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,15 +116,44 @@
 }
 
 /**
- *
- */
-function markup($texte)
-{
-    $texte = preg_replace('#\[([^|]+)\|(\s*javascript.*)\]#i', '$1', $texte);
-    $texte = preg_replace("/(\r\n|\r\n\r|\n|\n\r|\r)/", "\r", $texte);
+ * used by markup()
+ * convert a BBCode link to HTML <a>
+ * with a check on URL
+ *
+ * @params array $matches, array from preg_replace_callback
+ * @return string
+ */
+function markup_clean_href($matches)
+{
+    // var_dump($matches);
+    $allowed = array('http://', 'https://', 'ftp://');
+    // if not a valid url, return the string
+    if (!filter_var($matches['2'], FILTER_VALIDATE_URL)
+     || !preg_match('#^('.join('|', $allowed).')#i', $matches['2'])
+    ) {
+        return $matches['0'];
+    }
+    // handle different case
+    if (empty(trim($matches['1']))){
+        return $matches['1'].'<a href="'.$matches['2'].'">'.$matches['2'].'</a>';
+    } else {
+        return '<a href="'.$matches['2'].'">'.$matches['1'].'</a>';
+    }
+}
+
+/**
+ * convert text with BBCode (more or less BBCode) to HTML
+ *
+ * @params string $text
+ * @return string
+ */
+function markup($text)
+{
+    $text = preg_replace('#\[([^|]+)\|(\s*javascript.*)\]#i', '$1', $text);
+    $text = preg_replace("/(\r\n|\r\n\r|\n|\n\r|\r)/", "\r", $text);
     $tofind = array(
-        /* regex URL     */ '#([^"\[\]|])((http|ftp)s?://([^"\'\[\]<>\s\)\(]+))#i',
-        /* a href        */ '#\[([^[]+)\|([^[]+)\]#',
+        // /* regex URL     */ '#([^"\[\]|])((http|ftp)s?://([^"\'\[\]<>\s\)\(]+))#i',
+        // /* a href        */ '#\[([^[]+)\|([^[]+)\]#',
         /* strong        */ '#\[b\](.*?)\[/b\]#s',
         /* italic        */ '#\[i\](.*?)\[/i\]#s',
         /* strike        */ '#\[s\](.*?)\[/s\]#s',
@@ -134,8 +163,8 @@
         /* code=language */ '#\[code=(\w+)\]\[/code\]#s',
     );
     $toreplace = array(
-        /* regex URL     */ '$1<a href="$2">$2</a>',
-        /* a href        */ '<a href="$2">$1</a>',
+        // /* regex URL     */ '$1<a href="$2">$2</a>',
+        // /* a href        */ '<a href="$2">$1</a>',
         /* strong        */ '<b>$1</b>',
         /* italic        */ '<em>$1</em>',
         /* strike        */ '<del>$1</del>',
@@ -145,9 +174,11 @@
         /* code=language */ '<prebtcode data-language="$1"></prebtcode>'."\r",
     );
 
-    preg_match_all('#\[code(=(\w+))?\](.*?)\[/code\]#s', $texte, $code_contents, PREG_SET_ORDER);
-    $texte_formate = preg_replace('#\[code(=(\w+))?\](.*?)\[/code\]#s', '[code$1][/code]', $texte);
+    preg_match_all('#\[code(=(\w+))?\](.*?)\[/code\]#s', $text, $code_contents, PREG_SET_ORDER);
+    $texte_formate = preg_replace('#\[code(=(\w+))?\](.*?)\[/code\]#s', '[code$1][/code]', $text);
     $texte_formate = preg_replace($tofind, $toreplace, $texte_formate);
+    $texte_formate = preg_replace_callback('#([^"\[\]|])((http|ftp)s?://([^"\'\[\]<>\s\)\(]+))#i', 'markup_clean_href', $texte_formate);
+    $texte_formate = preg_replace_callback('#\[([^[]+)\|([^[]+)\]#', 'markup_clean_href', $texte_formate);
     $texte_formate = parse_texte_paragraphs($texte_formate);
     $texte_formate = parse_texte_code($texte_formate, $code_contents);
 
```
