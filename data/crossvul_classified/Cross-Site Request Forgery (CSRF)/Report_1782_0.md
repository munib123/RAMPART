# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1782_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1782_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 77-117 of the vulnerable file.

     */
    public function startup(Event $event)
    {
        $controller = $event->subject();
        $request = $controller->request;
        $response = $controller->response;
        $cookieName = $this->_config['cookieName'];

        $cookieData = $request->cookie($cookieName);
        if ($cookieData) {
            $request->params['_csrfToken'] = $cookieData;
        }

        if ($request->is('requested')) {
            return;
        }

        if ($request->is('get') && $cookieData === null) {
            $this->_setCookie($request, $response);
        }
        if ($request->is(['patch', 'put', 'post', 'delete'])) {
            $this->_validateToken($request);
            unset($request->data[$this->_config['field']]);
        }
    }

    /**
     * Events supported by this component.
     *
     * @return array
     */
    public function implementedEvents()
    {
        return [
            'Controller.startup' => 'startup',
        ];
    }

    /**
     * Set the cookie in the response.
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,7 +94,7 @@
         if ($request->is('get') && $cookieData === null) {
             $this->_setCookie($request, $response);
         }
-        if ($request->is(['patch', 'put', 'post', 'delete'])) {
+        if (!$request->is(['head', 'get', 'options'])) {
             $this->_validateToken($request);
             unset($request->data[$this->_config['field']]);
         }
```
