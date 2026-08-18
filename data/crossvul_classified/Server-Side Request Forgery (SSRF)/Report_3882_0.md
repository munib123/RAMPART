# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 3882_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3882_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 23-57 of the vulnerable file.

//	License agreement and license key will be shipped with the order
//	confirmation.

$config = [
    'acl_dependencies' => [
        'always_allowed' => [
            'GrafanaConfiguration'  => [
                'grafanaWidget',
                'getGrafanaDashboards'
            ],
            'GrafanaUserdashboards' => [
                'grafanaRow',
                'grafanaPanel',
                'getPerformanceDataMetrics',
                'grafanaWidget',
                'grafanaTimepicker',
            ]
        ],
        'dependencies'   => [
            'GrafanaConfiguration'  => [
                'index' => ['testGrafanaConnection', 'loadHostgroups'],
            ],
            'GrafanaUserdashboards' => [
                'add'    => ['loadContainers'],
                'edit'   => ['loadContainers'],
                'editor' => ['addMetricToPanel', 'removeMetricFromPanel', 'addPanel', 'removePanel', 'addRow', 'removeRow', 'savePanelUnit', 'synchronizeWithGrafana'],
                'view'   => ['getViewIframeUrl']
            ],

        ],
        'roles_rights'   => [
            'Administrator' => ['*'],
        ]
    ],
];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,7 +40,7 @@
         ],
         'dependencies'   => [
             'GrafanaConfiguration'  => [
-                'index' => ['testGrafanaConnection', 'loadHostgroups'],
+                'index' => ['loadHostgroups'],
             ],
             'GrafanaUserdashboards' => [
                 'add'    => ['loadContainers'],
```
