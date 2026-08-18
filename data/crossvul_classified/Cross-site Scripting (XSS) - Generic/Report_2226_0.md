# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2226_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2226_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 330-373 of the vulnerable file.

     * @param string $strParams
     * @param string $strSystemid
     * @param string $strLanguage
     * @param string $strSeoAddon Only used if using mod_rewrite
     * @return string
     */
    public static function getLinkPortalHref($strPageI, $strPageE = "", $strAction = "", $strParams = "", $strSystemid = "", $strLanguage = "", $strSeoAddon = "") {
        $strReturn = "";
        $bitInternal = true;

        //return "#" if neither an internal nor an external page is set
        if($strPageI == "" && $strPageE == "")
            return "#";

        //Internal links are more important than external links!
        if($strPageI == "" && $strPageE != "")
            $bitInternal = false;


        //create an array out of the params
        $strParsedSystemid = "";
        $arrParams = self::parseParamsString($strParams, $strParsedSystemid);
        if($strSystemid == "" && validateSystemid($strParsedSystemid))
            $strSystemid = $strParsedSystemid;

        // any anchors set to the page?
        $strAnchor = "";
        if(uniStrpos($strPageI, "#") !== false) {
            //get anchor, remove anchor from link
            $strAnchor = urlencode(uniSubstr($strPageI, uniStrpos($strPageI, "#")+1));
            $strPageI = uniSubstr($strPageI, 0, uniStrpos($strPageI, "#"));
        }

        //urlencoding
        $strPageI = urlencode($strPageI);
        $strAction = urlencode($strAction);

        //more than one language installed?
        if($strLanguage == "" && self::getIntNumberOfPortalLanguages() > 1)
            $strLanguage = self::getStrPortalLanguage();
        else if($strLanguage != "" && self::getIntNumberOfPortalLanguages() <=1)
            $strLanguage = "";

        $strHref = "";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -347,10 +347,12 @@
 
 
         //create an array out of the params
-        $strParsedSystemid = "";
-        $arrParams = self::parseParamsString($strParams, $strParsedSystemid);
-        if($strSystemid == "" && validateSystemid($strParsedSystemid))
-            $strSystemid = $strParsedSystemid;
+        if($strSystemid != "") {
+            $strParams .= "&systemid=".$strSystemid;
+            $strSystemid = "";
+        }
+
+        $arrParams = self::parseParamsString($strParams, $strSystemid);
 
         // any anchors set to the page?
         $strAnchor = "";
@@ -496,7 +498,11 @@
             $arrEntry = explode("=", $strValue);
 
             if(count($arrEntry) == 2 && $arrEntry[0] == "systemid") {
-                $strSystemid = $arrEntry[1];
+                //encoded and sanitized systemid param TODO: add cve number or other identifier
+                $strSystemid = urlencode($arrEntry[1]);
+                if(!validateSystemid($strSystemid))
+                    $strSystemid = "";
+
                 unset($arrParams[$strKey]);
             }
             else if($strValue == "")
```
