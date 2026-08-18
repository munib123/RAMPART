# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1227_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1227_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 116-156 of the vulnerable file.

     * @throws \Exception
     */
    public function showEmailLogAction(Request $request, ?Profiler $profiler)
    {
        if($profiler) {
            $profiler->disable();
        }

        if (!$this->getAdminUser()->isAllowed('emails')) {
            throw new \Exception("Permission denied, user needs 'emails' permission.");
        }

        $type = $request->get('type');
        $emailLog = Tool\Email\Log::getById($request->get('id'));

        if ($request->get('type') == 'text') {
            $templatingEnginePhp = $this->get('pimcore.templating.engine.php');

            return new Response('<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><style>body{background-color:#fff;}</style></head><body><pre>' . $templatingEnginePhp->escape($emailLog->getTextLog()) . '</pre></body></html>');
        } elseif ($request->get('type') == 'html') {
            return new Response($emailLog->getHtmlLog());
        } elseif ($request->get('type') == 'params') {
            try {
                $params = $this->decodeJson($emailLog->getParams());
            } catch (\Exception $e) {
                Logger::warning('Could not decode JSON param string');
                $params = [];
            }
            foreach ($params as &$entry) {
                $this->enhanceLoggingData($entry);
            }

            return $this->adminJson($params);
        } else {
            return new Response('No Type specified');
        }
    }

    /**
     * @param array $data
     * @param $fullEntry
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,7 +133,9 @@
 
             return new Response('<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><style>body{background-color:#fff;}</style></head><body><pre>' . $templatingEnginePhp->escape($emailLog->getTextLog()) . '</pre></body></html>');
         } elseif ($request->get('type') == 'html') {
-            return new Response($emailLog->getHtmlLog());
+            return new Response($emailLog->getHtmlLog(), 200, [
+                'Content-Security-Policy' => "default-src 'self'; style-src 'self' 'unsafe-inline'"
+            ]);
         } elseif ($request->get('type') == 'params') {
             try {
                 $params = $this->decodeJson($emailLog->getParams());
```
