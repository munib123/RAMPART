# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 4223_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4223_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 396-437 of the vulnerable file.

                'type' => 'root',
                'text' => __('Audit'),
                'requirement' =>  ($isAclAudit),
                'children' => array(
                    array(
                        'text' => __('List Logs'),
                        'url' => '/admin/logs/index'
                    ),
                    array(
                        'text' => __('Search Logs'),
                        'url' => '/admin/logs/search'
                    )
                )
            )
        );
        $menu_right = array(
            array(
                'type' => 'root',
                'url' => '#',
                'html' => sprintf(
                    '<span class="fas fa-star %s" id="setHomePage" title="Set the current page as your home page in MISP"></span>',
                    (!empty($homepage['path']) && $homepage['path'] === $this->here) ? 'orange' : ''
                )
            ),
            array(
                'type' => 'root',
                'url' =>empty($homepage['path']) ? $baseurl : $baseurl . h($homepage['path']),
                'html' => '<span class="logoBlueStatic bold" id="smallLogo">MISP</span>'
            ),
            array(
                'type' => 'root',
                'url' => '/dashboards',
                'html' => sprintf(
                    '<span class="white" title="%s">%s%s&nbsp;&nbsp;&nbsp;%s</span>',
                    h($me['email']),
                    $this->UserName->prepend($me['email']),
                    h($loggedInUserName),
                    sprintf(
                        '<i class="fa fa-envelope %s"></i>',
                        (($notifications['total'] == 0) ? 'white' : 'red')
                    )
                )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -413,8 +413,9 @@
                 'type' => 'root',
                 'url' => '#',
                 'html' => sprintf(
-                    '<span class="fas fa-star %s" id="setHomePage" title="Set the current page as your home page in MISP"></span>',
-                    (!empty($homepage['path']) && $homepage['path'] === $this->here) ? 'orange' : ''
+                    '<span class="fas fa-star %s" id="setHomePage" title="Set the current page as your home page in MISP" data-current-page="%s"></span>',
+                    (!empty($homepage['path']) && $homepage['path'] === $this->here) ? 'orange' : '',
+                    $this->here
                 )
             ),
             array(
```
