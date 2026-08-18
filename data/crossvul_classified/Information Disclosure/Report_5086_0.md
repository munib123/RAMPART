# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5086_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5086_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 135-175 of the vulnerable file.

                ? $GLOBALS['cfg']['Server']['verbose']
                : $GLOBALS['cfg']['Server']['host']);
}

echo '<div id="maincontainer">' , "\n";
// Anchor for favorite tables synchronization.
echo RecentFavoriteTable::getInstance('favorite')->getHtmlSyncFavoriteTables();
echo '<div id="main_pane_left">';
if ($server > 0 || count($cfg['Servers']) > 1
) {
    if ($cfg['DBG']['demo']) {
        echo '<div class="group">';
        echo '<h2>' , __('phpMyAdmin Demo Server') , '</h2>';
        echo '<p style="margin: 0.5em 1em 0.5em 1em">';
        printf(
            __(
                'You are using the demo server. You can do anything here, but '
                . 'please do not change root, debian-sys-maint and pma users. '
                . 'More information is available at %s.'
            ),
            '<a href="http://demo.phpmyadmin.net/">demo.phpmyadmin.net</a>'
        );
        echo '</p>';
        echo '</div>';
    }
    echo '<div class="group">';
    echo '<h2>' , __('General settings') , '</h2>';
    echo '<ul>';

    /**
     * Displays the MySQL servers choice form
     */
    if ($cfg['ServerDefault'] == 0
        || (! $cfg['NavigationDisplayServers']
        && (count($cfg['Servers']) > 1
        || ($server == 0 && count($cfg['Servers']) == 1)))
    ) {
        echo '<li id="li_select_server" class="no_bullets" >';
        include_once 'libraries/select_server.lib.php';
        echo PMA\libraries\Util::getImage('s_host.png') , " "
            , PMA_selectServer(true, true);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,7 +152,7 @@
                 . 'please do not change root, debian-sys-maint and pma users. '
                 . 'More information is available at %s.'
             ),
-            '<a href="http://demo.phpmyadmin.net/">demo.phpmyadmin.net</a>'
+            '<a href="url.php?url=http://demo.phpmyadmin.net/">demo.phpmyadmin.net</a>'
         );
         echo '</p>';
         echo '</div>';
```
