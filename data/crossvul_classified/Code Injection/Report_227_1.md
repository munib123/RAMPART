# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 227_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `227_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php

/*
 * This file is part of Twig.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Stores the Twig configuration.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class Twig_Environment
{
    const VERSION = '2.4.4-DEV';
    const VERSION_ID = 20404;
    const MAJOR_VERSION = 2;
    const MINOR_VERSION = 4;
    const RELEASE_VERSION = 4;
    const EXTRA_VERSION = 'DEV';

    private $charset;
    private $loader;
    private $debug;
    private $autoReload;
    private $cache;
    private $lexer;
    private $parser;
    private $compiler;
    private $baseTemplateClass;
    private $globals = array();
    private $resolvedGlobals;
    private $loadedTemplates;
    private $strictVariables;
    private $templateClassPrefix = '__TwigTemplate_';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,12 +16,12 @@
  */
 class Twig_Environment
 {
-    const VERSION = '2.4.4-DEV';
+    const VERSION = '2.4.4';
     const VERSION_ID = 20404;
     const MAJOR_VERSION = 2;
     const MINOR_VERSION = 4;
     const RELEASE_VERSION = 4;
-    const EXTRA_VERSION = 'DEV';
+    const EXTRA_VERSION = '';
 
     private $charset;
     private $loader;
```
