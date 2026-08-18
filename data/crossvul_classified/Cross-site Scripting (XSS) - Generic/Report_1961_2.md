# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1961_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1961_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 147-187 of the vulnerable file.

        }

        if ($this->disablePager) {
            $use_pager = false;
        } elseif ($this->statsBreakdown == 'week') {
            $per_page  = 4;
            $use_pager = count($stats) > $per_page;
        } elseif ($this->aGlobalPrefs['period_preset'] == 'this_month' || $this->aGlobalPrefs['period_preset'] == 'last_month') {
            // Do not use pager when showing last or current month
            $use_pager = false;
        } elseif ($this->statsBreakdown == 'hour' || $this->statsBreakdown == 'dow') {
            $use_pager = false;
        } else {
            $per_page  = 15;
            $use_pager = count($stats) > $per_page;
        }

        if ($use_pager) {
            $params = array(
                'itemData' => $stats,
                'perPage' => htmlspecialchars(MAX_getStoredValue('setPerPage', $per_page)),
                'delta' => 8,
                'append' => true,
                'clearIfVoid' => false,
                'urlVar' => 'page',
                'useSessions' => false,
                'mode'  => 'Jumping'
            );

            if ($params['perPage'] % $per_page || $params['perPage'] > $per_page * 4) {
                // Reset the perPage and the request parameters when not matching the available values
                $params['perPage']      = $per_page;
                $_REQUEST['setPerPage'] = $per_page;
            }

            $pager =& Pager::factory($params);
            $this->aStatsData = $pager->getPageData();
            $this->pagerLinks = $pager->getLinks();
            $this->pagerLinks = $this->pagerLinks['all'];

            $this->pagerSelect = preg_replace('/(<select.*?)(>)/i', '$1 onchange="this.form.submit()"$2',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -164,7 +164,7 @@
         if ($use_pager) {
             $params = array(
                 'itemData' => $stats,
-                'perPage' => htmlspecialchars(MAX_getStoredValue('setPerPage', $per_page)),
+                'perPage' => (int) MAX_getStoredValue('setPerPage', $per_page),
                 'delta' => 8,
                 'append' => true,
                 'clearIfVoid' => false,
```
