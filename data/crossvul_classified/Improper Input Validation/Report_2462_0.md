# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2462_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2462_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1-35 of the vulnerable file.

<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\ErrorHandler\ErrorRenderer;

use Symfony\Component\ErrorHandler\Exception\FlattenException;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;
use Symfony\Component\Serializer\SerializerInterface;

/**
 * Formats an exception using Serializer for rendering.
 *
 * @author Nicolas Grekas <p@tchwork.com>
 */
class SerializerErrorRenderer implements ErrorRendererInterface
{
    private $serializer;
    private $format;
    private $fallbackErrorRenderer;
    private $debug;

    /**
     * @param string|callable(FlattenException) $format The format as a string or a callable that should return it
     * @param bool|callable                     $debug  The debugging mode as a boolean or a callable that should return it
     */
    public function __construct(SerializerInterface $serializer, $format, ErrorRendererInterface $fallbackErrorRenderer = null, $debug = false)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,7 @@
 namespace Symfony\Component\ErrorHandler\ErrorRenderer;
 
 use Symfony\Component\ErrorHandler\Exception\FlattenException;
+use Symfony\Component\HttpFoundation\Request;
 use Symfony\Component\HttpFoundation\RequestStack;
 use Symfony\Component\Serializer\Exception\NotEncodableValueException;
 use Symfony\Component\Serializer\SerializerInterface;
@@ -30,6 +31,7 @@
 
     /**
      * @param string|callable(FlattenException) $format The format as a string or a callable that should return it
+     *                                                  formats not supported by Request::getMimeTypes() should be given as mime types
      * @param bool|callable                     $debug  The debugging mode as a boolean or a callable that should return it
      */
     public function __construct(SerializerInterface $serializer, $format, ErrorRendererInterface $fallbackErrorRenderer = null, $debug = false)
@@ -57,11 +59,16 @@
 
         try {
             $format = \is_string($this->format) ? $this->format : ($this->format)($flattenException);
+            $headers = [
+                'Content-Type' => Request::getMimeTypes($format)[0] ?? $format,
+                'Vary' => 'Accept',
+            ];
 
             return $flattenException->setAsString($this->serializer->serialize($flattenException, $format, [
                 'exception' => $exception,
                 'debug' => \is_bool($this->debug) ? $this->debug : ($this->debug)($exception),
-            ]));
+            ]))
+            ->setHeaders($flattenException->getHeaders() + $headers);
         } catch (NotEncodableValueException $e) {
             return $this->fallbackErrorRenderer->render($exception);
         }
```
