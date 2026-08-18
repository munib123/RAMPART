# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1782_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1782_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 44-85 of the vulnerable file.


    /**
     * teardown
     *
     * @return void
     */
    public function tearDown()
    {
        parent::tearDown();
        unset($this->component);
    }

    /**
     * Test setting the cookie value
     *
     * @return void
     * @triggers Controller.startup $controller
     */
    public function testSettingCookie()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
        $controller->request = new Request(['webroot' => '/dir/']);
        $controller->response = new Response();

        $event = new Event('Controller.startup', $controller);
        $this->component->startup($event);

        $cookie = $controller->response->cookie('csrfToken');
        $this->assertNotEmpty($cookie, 'Should set a token.');
        $this->assertRegExp('/^[a-f0-9]+$/', $cookie['value'], 'Should look like a hash.');
        $this->assertEquals(0, $cookie['expire'], 'session duration.');
        $this->assertEquals('/dir/', $cookie['path'], 'session path.');

        $this->assertEquals($cookie['value'], $controller->request->params['_csrfToken']);
    }

    /**
     * Data provider for HTTP method tests.
     *
     * @return void
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,10 +61,11 @@
      */
     public function testSettingCookie()
     {
-        $_SERVER['REQUEST_METHOD'] = 'GET';
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request(['webroot' => '/dir/']);
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => ['REQUEST_METHOD' => 'GET'],
+            'webroot' => '/dir/',
+        ]);
         $controller->response = new Response();
 
         $event = new Event('Controller.startup', $controller);
@@ -87,7 +88,7 @@
     public static function httpMethodProvider()
     {
         return [
-            ['PATCH'], ['PUT'], ['POST'], ['DELETE']
+            ['PATCH'], ['PUT'], ['POST'], ['DELETE'], ['PURGE'], ['INVALIDMETHOD']
         ];
     }
 
@@ -100,11 +101,14 @@
      */
     public function testValidTokenInHeader($method)
     {
-        $_SERVER['REQUEST_METHOD'] = $method;
-        $_SERVER['HTTP_X_CSRF_TOKEN'] = 'testing123';
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request(['cookies' => ['csrfToken' => 'testing123']]);
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => [
+                'REQUEST_METHOD' => $method,
+                'HTTP_X_CSRF_TOKEN' => 'testing123',
+            ],
+            'cookies' => ['csrfToken' => 'testing123']
+        ]);
         $controller->response = new Response();
 
         $event = new Event('Controller.startup', $controller);
@@ -122,11 +126,12 @@
      */
     public function testInvalidTokenInHeader($method)
     {
-        $_SERVER['REQUEST_METHOD'] = $method;
-        $_SERVER['HTTP_X_CSRF_TOKEN'] = 'nope';
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request([
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => [
+                'REQUEST_METHOD' => $method,
+                'HTTP_X_CSRF_TOKEN' => 'nope',
+            ],
             'cookies' => ['csrfToken' => 'testing123']
         ]);
         $controller->response = new Response();
@@ -144,10 +149,11 @@
      */
     public function testValidTokenRequestData($method)
     {
-        $_SERVER['REQUEST_METHOD'] = $method;
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request([
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => [
+                'REQUEST_METHOD' => $method,
+            ],
             'post' => ['_csrfToken' => 'testing123'],
             'cookies' => ['csrfToken' => 'testing123']
         ]);
@@ -168,10 +174,11 @@
      */
     public function testInvalidTokenRequestData($method)
     {
-        $_SERVER['REQUEST_METHOD'] = $method;
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request([
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => [
+                'REQUEST_METHOD' => $method,
+            ],
             'post' => ['_csrfToken' => 'nope'],
             'cookies' => ['csrfToken' => 'testing123']
         ]);
@@ -189,10 +196,11 @@
      */
     public function testInvalidTokenRequestDataMissing()
     {
-        $_SERVER['REQUEST_METHOD'] = 'POST';
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request([
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => [
+                'REQUEST_METHOD' => 'POST',
+            ],
             'post' => [],
             'cookies' => ['csrfToken' => 'testing123']
         ]);
@@ -211,10 +219,11 @@
      */
     public function testInvalidTokenMissingCookie($method)
     {
-        $_SERVER['REQUEST_METHOD'] = $method;
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request([
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => [
+                'REQUEST_METHOD' => $method
+            ],
             'post' => ['_csrfToken' => 'could-be-valid'],
             'cookies' => []
         ]);
@@ -232,10 +241,9 @@
      */
     public function testCsrfValidationSkipsRequestAction()
     {
-        $_SERVER['REQUEST_METHOD'] = 'POST';
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request([
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => ['REQUEST_METHOD' => 'POST'],
             'params' => ['requested' => 1],
             'post' => ['_csrfToken' => 'nope'],
             'cookies' => ['csrfToken' => 'testing123']
@@ -256,10 +264,11 @@
      */
     public function testConfigurationCookieCreate()
     {
-        $_SERVER['REQUEST_METHOD'] = 'GET';
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request(['webroot' => '/dir/']);
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => ['REQUEST_METHOD' => 'GET'],
+            'webroot' => '/dir/'
+        ]);
         $controller->response = new Response();
 
         $component = new CsrfComponent($this->registry, [
@@ -290,10 +299,9 @@
      */
     public function testConfigurationValidate()
     {
-        $_SERVER['REQUEST_METHOD'] = 'POST';
-
-        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
-        $controller->request = new Request([
+        $controller = $this->getMock('Cake\Controller\Controller', ['redirect']);
+        $controller->request = new Request([
+            'environment' => ['REQUEST_METHOD' => 'POST'],
             'cookies' => ['csrfToken' => 'nope', 'token' => 'yes'],
             'post' => ['_csrfToken' => 'no match', 'token' => 'yes'],
         ]);
```
