# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 4182_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4182_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
namespace TYPO3Fluid\Fluid\Core\Parser\Interceptor;

/*
 * This file belongs to the package "TYPO3 Fluid".
 * See LICENSE.txt that was shipped with this package.
 */

use TYPO3Fluid\Fluid\Core\Parser\InterceptorInterface;
use TYPO3Fluid\Fluid\Core\Parser\ParsingState;
use TYPO3Fluid\Fluid\Core\Parser\SyntaxTree\EscapingNode;
use TYPO3Fluid\Fluid\Core\Parser\SyntaxTree\NodeInterface;
use TYPO3Fluid\Fluid\Core\Parser\SyntaxTree\ObjectAccessorNode;
use TYPO3Fluid\Fluid\Core\Parser\SyntaxTree\ViewHelperNode;

/**
 * An interceptor adding the "Htmlspecialchars" viewhelper to the suitable places.
 */
class Escape implements InterceptorInterface
{

    /**
     * Is the interceptor enabled right now for child nodes?
     *
     * @var boolean
     */
    protected $childrenEscapingEnabled = true;

    /**
     * A stack of ViewHelperNodes which currently disable the interceptor.
     * Needed to enable the interceptor again.
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 use TYPO3Fluid\Fluid\Core\Parser\InterceptorInterface;
 use TYPO3Fluid\Fluid\Core\Parser\ParsingState;
 use TYPO3Fluid\Fluid\Core\Parser\SyntaxTree\EscapingNode;
+use TYPO3Fluid\Fluid\Core\Parser\SyntaxTree\Expression\ExpressionNodeInterface;
 use TYPO3Fluid\Fluid\Core\Parser\SyntaxTree\NodeInterface;
 use TYPO3Fluid\Fluid\Core\Parser\SyntaxTree\ObjectAccessorNode;
 use TYPO3Fluid\Fluid\Core\Parser\SyntaxTree\ViewHelperNode;
@@ -62,7 +63,7 @@
             if ($this->childrenEscapingEnabled && $node->getUninitializedViewHelper()->isOutputEscapingEnabled()) {
                 $node = new EscapingNode($node);
             }
-        } elseif ($this->childrenEscapingEnabled && $node instanceof ObjectAccessorNode) {
+        } elseif ($this->childrenEscapingEnabled && ($node instanceof ObjectAccessorNode || $node instanceof ExpressionNodeInterface)) {
             $node = new EscapingNode($node);
         }
         return $node;
@@ -78,7 +79,8 @@
         return [
             InterceptorInterface::INTERCEPT_OPENING_VIEWHELPER,
             InterceptorInterface::INTERCEPT_CLOSING_VIEWHELPER,
-            InterceptorInterface::INTERCEPT_OBJECTACCESSOR
+            InterceptorInterface::INTERCEPT_OBJECTACCESSOR,
+            InterceptorInterface::INTERCEPT_EXPRESSION,
         ];
     }
 }
```
