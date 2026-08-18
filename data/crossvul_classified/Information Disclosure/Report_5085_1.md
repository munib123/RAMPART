# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5085_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5085_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 150-191 of the vulnerable file.

     */
    private function _links()
    {
        // always iconic
        $showIcon = true;
        $showText = false;

        $retval = '<!-- LINKS START -->';
        $retval .= '<div id="navipanellinks">';
        $retval .= PMA\libraries\Util::getNavigationLink(
            'index.php' . PMA_URL_getCommon(),
            $showText,
            __('Home'),
            $showIcon,
            'b_home.png'
        );
        // if we have chosen server
        if ($GLOBALS['server'] != 0) {
            // Logout for advanced authentication
            if ($GLOBALS['cfg']['Server']['auth_type'] != 'config') {
                $link = 'index.php' . $GLOBALS['url_query'];
                $link .= '&amp;old_usr=' . urlencode($GLOBALS['PHP_AUTH_USER']);
                $retval .= PMA\libraries\Util::getNavigationLink(
                    $link,
                    $showText,
                    __('Log out'),
                    $showIcon,
                    's_loggoff.png',
                    '',
                    true
                );
            }
        }
        $retval .= PMA\libraries\Util::getNavigationLink(
            PMA\libraries\Util::getDocuLink('index'),
            $showText,
            __('phpMyAdmin documentation'),
            $showIcon,
            'b_docs.png',
            '',
            false,
            'documentation'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -167,8 +167,7 @@
         if ($GLOBALS['server'] != 0) {
             // Logout for advanced authentication
             if ($GLOBALS['cfg']['Server']['auth_type'] != 'config') {
-                $link = 'index.php' . $GLOBALS['url_query'];
-                $link .= '&amp;old_usr=' . urlencode($GLOBALS['PHP_AUTH_USER']);
+                $link = 'logout.php' . $GLOBALS['url_query'];
                 $retval .= PMA\libraries\Util::getNavigationLink(
                     $link,
                     $showText,
```
