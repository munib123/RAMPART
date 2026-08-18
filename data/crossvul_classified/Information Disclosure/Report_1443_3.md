# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1443_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1443_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php

/*
 * This file is part of Twig.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Twig\NodeVisitor;

use Twig\Environment;
use Twig\Node\CheckSecurityNode;
use Twig\Node\Expression\Binary\RangeBinary;
use Twig\Node\Expression\FilterExpression;
use Twig\Node\Expression\FunctionExpression;
use Twig\Node\ModuleNode;
use Twig\Node\Node;
use Twig\Node\PrintNode;
use Twig\Node\SandboxedPrintNode;

/**
 * @final
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class SandboxNodeVisitor extends AbstractNodeVisitor
{
    protected $inAModule = false;
    protected $tags;
    protected $filters;
    protected $functions;

    protected function doEnterNode(Node $node, Environment $env)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,13 +13,17 @@
 
 use Twig\Environment;
 use Twig\Node\CheckSecurityNode;
+use Twig\Node\CheckToStringNode;
+use Twig\Node\Expression\Binary\ConcatBinary;
 use Twig\Node\Expression\Binary\RangeBinary;
 use Twig\Node\Expression\FilterExpression;
 use Twig\Node\Expression\FunctionExpression;
+use Twig\Node\Expression\GetAttrExpression;
+use Twig\Node\Expression\NameExpression;
 use Twig\Node\ModuleNode;
 use Twig\Node\Node;
 use Twig\Node\PrintNode;
-use Twig\Node\SandboxedPrintNode;
+use Twig\Node\SetNode;
 
 /**
  * @final
@@ -32,6 +36,8 @@
     protected $tags;
     protected $filters;
     protected $functions;
+
+    private $needsToStringWrap = false;
 
     protected function doEnterNode(Node $node, Environment $env)
     {
@@ -63,9 +69,28 @@
                 $this->functions['range'] = $node;
             }
 
-            // wrap print to check __toString() calls
             if ($node instanceof PrintNode) {
-                return new SandboxedPrintNode($node->getNode('expr'), $node->getTemplateLine(), $node->getNodeTag());
+                $this->needsToStringWrap = true;
+                $this->wrapNode($node, 'expr');
+            }
+
+            if ($node instanceof SetNode && !$node->getAttribute('capture')) {
+                $this->needsToStringWrap = true;
+            }
+
+            // wrap outer nodes that can implicitly call __toString()
+            if ($this->needsToStringWrap) {
+                if ($node instanceof ConcatBinary) {
+                    $this->wrapNode($node, 'left');
+                    $this->wrapNode($node, 'right');
+                }
+                if ($node instanceof FilterExpression) {
+                    $this->wrapNode($node, 'node');
+                    $this->wrapArrayNode($node, 'arguments');
+                }
+                if ($node instanceof FunctionExpression) {
+                    $this->wrapArrayNode($node, 'arguments');
+                }
             }
         }
 
@@ -78,9 +103,29 @@
             $this->inAModule = false;
 
             $node->setNode('constructor_end', new Node([new CheckSecurityNode($this->filters, $this->tags, $this->functions), $node->getNode('display_start')]));
+        } elseif ($this->inAModule) {
+            if ($node instanceof PrintNode || $node instanceof SetNode) {
+                $this->needsToStringWrap = false;
+            }
         }
 
         return $node;
+    }
+
+    private function wrapNode(Node $node, $name)
+    {
+        $expr = $node->getNode($name);
+        if ($expr instanceof NameExpression || $expr instanceof GetAttrExpression) {
+            $node->setNode($name, new CheckToStringNode($expr));
+        }
+    }
+
+    private function wrapArrayNode(Node $node, $name)
+    {
+        $args = $node->getNode($name);
+        foreach ($args as $name => $_) {
+            $this->wrapNode($args, $name);
+        }
     }
 
     public function getPriority()
```
