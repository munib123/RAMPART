# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2005_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2005_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 447-487 of the vulnerable file.

                    array(
                        'text' => __('List Logs'),
                        'url' => $baseurl . '/admin/logs/index'
                    ),
                    array(
                        'text' => __('Search Logs'),
                        'url' => $baseurl . '/admin/logs/search'
                    )
                )
            )
        );
        $menu_right = array(
            array(
                'type' => 'root',
                'url' => '#',
                'html' => sprintf(
                    '<span class="fas fa-star %s" id="setHomePage" title="%s" role="img" aria-label="%s" data-current-page="%s"></span>',
                    (!empty($homepage['path']) && $homepage['path'] === $this->here) ? 'orange' : '',
		    __('Set the current page as your home page in MISP'),
		    __('Set the current page as your home page in MISP'),
                    $this->here
                )
            ),
            array(
                'type' => 'root',
                'url' => empty($homepage['path']) ? $baseurl : $baseurl . h($homepage['path']),
                'html' => '<span class="logoBlueStatic bold" id="smallLogo">MISP</span>'
            ),
            array(
                'type' => 'root',
                'url' => $baseurl . '/dashboards',
                'html' => sprintf(
                    '<span class="white" title="%s">%s%s&nbsp;&nbsp;&nbsp;%s</span>',
                    h($me['email']),
                    $this->UserName->prepend($me['email']),
                    h($loggedInUserName),
                    isset($notifications) ? sprintf(
                        '<i class="fa fa-envelope %s" role="img" aria-label="%s"></i>',
                        (($notifications['total'] == 0) ? 'white' : 'red'),
                        __('Notifications') . ': ' . $notifications['total']
                    ) : ''
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -464,7 +464,7 @@
                     (!empty($homepage['path']) && $homepage['path'] === $this->here) ? 'orange' : '',
 		    __('Set the current page as your home page in MISP'),
 		    __('Set the current page as your home page in MISP'),
-                    $this->here
+                    h($this->here)
                 )
             ),
             array(
```
