# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 4500_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4500_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-40 of the vulnerable file.

<?php

namespace Bolt\Controller;

use Bolt\Asset\File\JavaScript;
use Bolt\Asset\File\Stylesheet;
use Bolt\Asset\Snippet\Snippet;
use Bolt\Asset\Target;
use Bolt\Helpers\Input;
use Bolt\Response\TemplateResponse;
use Bolt\Storage\Entity\Content;
use Bolt\Storage\Entity\Relations;
use Bolt\Storage\Entity\Taxonomy;
use Bolt\Storage\EntityManager;
use Bolt\Storage\Mapping\ContentType;
use Bolt\Storage\Query\QueryResultset;
use Bolt\Storage\Repository\TaxonomyRepository;
use Bolt\Translation\Translator as Trans;
use Silex\ControllerCollection;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;

/**
 * Standard Frontend actions.
 *
 * This file acts as a grouping for the default front-end controllers.
 *
 * For overriding the default behavior here, please reference
 * https://docs.bolt.cm/templating/templates-routes#routing or the routing.yml
 * file in your configuration.
 */
class Frontend extends ConfigurableBase
{
    protected function getConfigurationRoutes()
    {
        return $this->app['config']->get('routing', []);
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,7 @@
 use Bolt\Storage\Repository\TaxonomyRepository;
 use Bolt\Translation\Translator as Trans;
 use Silex\ControllerCollection;
+use Symfony\Component\HttpFoundation\JsonResponse;
 use Symfony\Component\HttpFoundation\RedirectResponse;
 use Symfony\Component\HttpFoundation\Request;
 use Symfony\Component\HttpFoundation\Response;
@@ -201,6 +202,12 @@
     {
         if (!$request->isMethod('POST')) {
             throw new MethodNotAllowedHttpException(['POST'], 'This route only accepts POST requests.');
+        }
+
+        // Only accept requests with a valid token
+        $tokenValue = $request->request->get('content_edit', ['_token' => null])['_token'];
+        if (!$this->isAllowed('dashboard') || !$this->isCsrfTokenValid($tokenValue, 'content_edit')) {
+            return new Response('Not allowed or invalid CSRF token', Response::HTTP_FORBIDDEN);
         }
 
         $contenttype = $this->getContentType($contenttypeslug);
```
