# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2085_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2085_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 192-232 of the vulnerable file.

    {
        if (empty($url)) {
            return BASE_URL.'/static/';
        }

        return BASE_URL.'/static/'.$url;
    }

    /**
     * Escape the given string.
     *
     * @param  string $string
     * @return string
     */
    public function escape($string)
    {
        return htmlspecialchars($string, ENT_QUOTES);
    }

    /**
     * Creates a full url for the given parts.
     *
     * @param  array   $urlArray
     * @param  string  $route
     * @param  boolean $secure
     * @return string
     */
    public function getUrl($urlArray = array(), $route = null, $secure  = false)
    {
        $config = \Ilch\Registry::get('config');

        if($config !== null && $this->_modRewrite === null) {
            $this->_modRewrite = (bool)$config->get('mod_rewrite');
        }

        if (empty($urlArray)) {
            return BASE_URL;
        }

        if (is_string($urlArray)) {
            return BASE_URL.'/index.php/'.$urlArray;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -209,6 +209,31 @@
     }
 
     /**
+     * Gets html from bbcode.
+     *
+     * @param string $bbcode
+     * @return string
+     */
+    public function getHtmlFromBBCode($bbcode)
+    {
+        require_once APPLICATION_PATH.'/libraries/jbbcode/Parser.php';
+        
+        $parser = new \JBBCode\Parser();
+        $parser->addCodeDefinitionSet(new \JBBCode\DefaultCodeDefinitionSet());
+        
+        $builder = new \JBBCode\CodeDefinitionBuilder('quote', '<div class="quote">{param}</div>');
+        $parser->addCodeDefinition($builder->build());
+
+        $builder = new \JBBCode\CodeDefinitionBuilder('code', '<pre class="code">{param}</pre>');
+        $builder->setParseContent(false);
+        $parser->addCodeDefinition($builder->build());
+        
+        $parser->parse($bbcode);
+
+        return $parser->getAsHTML();
+    }
+
+    /**
      * Creates a full url for the given parts.
      *
      * @param  array   $urlArray
```
