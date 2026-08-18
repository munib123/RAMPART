# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5165_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5165_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 622-662 of the vulnerable file.

        $dir  = $GLOBALS['text_dir'];

        $retval  = "<!DOCTYPE HTML>";
        $retval .= "<html lang='$lang' dir='$dir' class='";
        $retval .= mb_strtolower(PMA_USR_BROWSER_AGENT) . " ";
        $retval .= mb_strtolower(PMA_USR_BROWSER_AGENT)
            . intval(PMA_USR_BROWSER_VER) . "'>";
        $retval .= '<head>';

        return $retval;
    }

    /**
     * Returns the META tags
     *
     * @return string the META tags
     */
    private function _getMetaTags()
    {
        $retval  = '<meta charset="utf-8" />';
        $retval .= '<meta name="referrer" content="none" />';
        $retval .= '<meta name="robots" content="noindex,nofollow" />';
        $retval .= '<meta http-equiv="X-UA-Compatible" content="IE=Edge">';
        if (! $GLOBALS['cfg']['AllowThirdPartyFraming']) {
            $retval .= '<style id="cfs-style">html{display: none;}</style>';
        }
        return $retval;
    }

    /**
     * Returns the LINK tags for the favicon and the stylesheets
     *
     * @return string the LINK tags
     */
    private function _getLinkTags()
    {
        $retval = '<link rel="icon" href="favicon.ico" '
            . 'type="image/x-icon" />'
            . '<link rel="shortcut icon" href="favicon.ico" '
            . 'type="image/x-icon" />';
        // stylesheets
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -639,7 +639,7 @@
     private function _getMetaTags()
     {
         $retval  = '<meta charset="utf-8" />';
-        $retval .= '<meta name="referrer" content="none" />';
+        $retval .= '<meta name="referrer" content="no-referrer" />';
         $retval .= '<meta name="robots" content="noindex,nofollow" />';
         $retval .= '<meta http-equiv="X-UA-Compatible" content="IE=Edge">';
         if (! $GLOBALS['cfg']['AllowThirdPartyFraming']) {
```
