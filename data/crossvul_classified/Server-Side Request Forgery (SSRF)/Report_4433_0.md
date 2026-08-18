# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 4433_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4433_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 1985-2025 of the vulnerable file.

            $allValidApisFormated[$endpoint_data['controller']][] = array('url' => $endpoint_url, 'action' => $endpoint_data['action']);
        }
        $this->set('allValidApisFormated', $allValidApisFormated);
        $this->set('allValidApisFieldsContraint', $allValidApisFieldsContraint);
    }

    private function __doRestQuery($request, &$curl = false, &$python = false)
    {
        App::uses('SyncTool', 'Tools');
        $params = array();
        $this->loadModel('RestClientHistory');
        $this->RestClientHistory->create();
        $date = new DateTime();
        $rest_history_item = array(
            'org_id' => $this->Auth->user('org_id'),
            'user_id' => $this->Auth->user('id'),
            'headers' => $request['header'],
            'body' => empty($request['body']) ? '' : $request['body'],
            'url' => $request['url'],
            'http_method' => $request['method'],
            'use_full_path' => $request['use_full_path'],
            'show_result' => $request['show_result'],
            'skip_ssl' => $request['skip_ssl_validation'],
            'bookmark' => $request['bookmark'],
            'bookmark_name' => $request['name'],
            'timestamp' => $date->getTimestamp()
        );
        if (!empty($request['url'])) {
            if (empty($request['use_full_path'])) {
                $path = preg_replace('#^(://|[^/?])+#', '', $request['url']);
                $url = Configure::read('MISP.baseurl') . $path;
                unset($request['url']);
            } else {
                $url = $request['url'];
            }
        } else {
            throw new InvalidArgumentException('Url not set.');
        }
        if (!empty($request['skip_ssl_validation'])) {
            $params['ssl_verify_peer'] = false;
            $params['ssl_verify_host'] = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2002,7 +2002,7 @@
             'body' => empty($request['body']) ? '' : $request['body'],
             'url' => $request['url'],
             'http_method' => $request['method'],
-            'use_full_path' => $request['use_full_path'],
+            'use_full_path' => empty($request['use_full_path']) ? false : $request['use_full_path'],
             'show_result' => $request['show_result'],
             'skip_ssl' => $request['skip_ssl_validation'],
             'bookmark' => $request['bookmark'],
@@ -2010,9 +2010,9 @@
             'timestamp' => $date->getTimestamp()
         );
         if (!empty($request['url'])) {
-            if (empty($request['use_full_path'])) {
+            if (empty($request['use_full_path']) || empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
                 $path = preg_replace('#^(://|[^/?])+#', '', $request['url']);
-                $url = Configure::read('MISP.baseurl') . $path;
+                $url = empty(Configure::read('Security.rest_client_baseurl')) ? (Configure::read('MISP.baseurl') . $path) : (Configure::read('Security.rest_client_baseurl') . $path);
                 unset($request['url']);
             } else {
                 $url = $request['url'];
@@ -2082,6 +2082,7 @@
         }
         $view_data['duration'] = microtime(true) - $start;
         $view_data['duration'] = round($view_data['duration'] * 1000, 2) . 'ms';
+        $view_data['url'] = $url;
         $view_data['code'] =  $response->code;
         $view_data['headers'] = $response->headers;
         if (!empty($request['show_result'])) {
```
