# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 4500_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4500_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 311-352 of the vulnerable file.


    public function testPreview()
    {
        $this->setRequest(Request::create('/pages', 'POST'));
        $this->controller()->listing($this->getRequest(), 'pages/test');

        $templates = $this->getMockBuilder(TemplateChooser::class)
            ->setMethods(['record'])
            ->setConstructorArgs([$this->getApp()['config']])
            ->getMock()
        ;
        $templates
            ->expects($this->any())
            ->method('record')
            ->will($this->returnValue('record.twig'))
        ;
        $this->setService('templatechooser', $templates);

        $response = $this->controller()->preview($this->getRequest(), 'pages');

        $this->assertTrue($response instanceof TemplateView);
        $this->assertSame('record.twig', $response->getTemplate());
    }

    public function testListing()
    {
        $this->setRequest(Request::create('/pages'));
        $response = $this->controller()->listing($this->getRequest(), 'pages');

        $this->assertSame('listing.twig', $response->getTemplate());
        $this->assertTrue($response instanceof TemplateView);
    }

    /**
     * @group legacy
     */
    public function testLegacyListing()
    {
        $this->getService('config')->set('general/compatibility/template_view', false);
        $this->setRequest(Request::create('/pages'));
        $response = $this->controller()->listing($this->getRequest(), 'pages');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -328,8 +328,7 @@
 
         $response = $this->controller()->preview($this->getRequest(), 'pages');
 
-        $this->assertTrue($response instanceof TemplateView);
-        $this->assertSame('record.twig', $response->getTemplate());
+        $this->assertFalse($response instanceof TemplateView);
     }
 
     public function testListing()
```
