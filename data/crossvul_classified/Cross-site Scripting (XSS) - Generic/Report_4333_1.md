# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4333_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4333_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 472-512 of the vulnerable file.

        // The following post-processing handles a case when there is only a ViewHelper, and no Object Accessor.
        // Resolves bug #5107.
        if (strlen($delimiter) === 0 && strlen($viewHelperString) > 0) {
            $viewHelperString = $objectAccessorString . $viewHelperString;
            $objectAccessorString = '';
        }

        // ViewHelpers
        $matches = [];
        if (strlen($viewHelperString) > 0 && preg_match_all(Patterns::$SPLIT_PATTERN_SHORTHANDSYNTAX_VIEWHELPER, $viewHelperString, $matches, PREG_SET_ORDER) > 0) {
            // The last ViewHelper has to be added first for correct chaining.
            // Note that ignoring namespaces is NOT possible in inline syntax; any inline syntax that contains a namespace
            // which is invalid will be reported as an error regardless of whether the namespace is marked as ignored.
            $viewHelperResolver = $this->renderingContext->getViewHelperResolver();
            foreach (array_reverse($matches) as $singleMatch) {
                if (!$viewHelperResolver->isNamespaceValid($singleMatch['NamespaceIdentifier'])) {
                    throw new UnknownNamespaceException('Unknown Namespace: ' . $singleMatch['NamespaceIdentifier']);
                }
                $viewHelper = $viewHelperResolver->createViewHelperInstance($singleMatch['NamespaceIdentifier'], $singleMatch['MethodIdentifier']);
                if (strlen($singleMatch['ViewHelperArguments']) > 0) {
                    $arguments = $this->recursiveArrayHandler($singleMatch['ViewHelperArguments'], $viewHelper);
                } else {
                    $arguments = [];
                }
                $viewHelperNode = $this->initializeViewHelperAndAddItToStack(
                    $state,
                    $singleMatch['NamespaceIdentifier'],
                    $singleMatch['MethodIdentifier'],
                    $arguments
                );
                if ($viewHelperNode) {
                    $numberOfViewHelpers++;
                }
            }
        }

        // Object Accessor
        if (strlen($objectAccessorString) > 0) {
            $node = new ObjectAccessorNode($objectAccessorString);
            $this->callInterceptor($node, InterceptorInterface::INTERCEPT_OBJECTACCESSOR, $state);
            $state->getNodeFromStack()->addChildNode($node);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -489,7 +489,7 @@
                 }
                 $viewHelper = $viewHelperResolver->createViewHelperInstance($singleMatch['NamespaceIdentifier'], $singleMatch['MethodIdentifier']);
                 if (strlen($singleMatch['ViewHelperArguments']) > 0) {
-                    $arguments = $this->recursiveArrayHandler($singleMatch['ViewHelperArguments'], $viewHelper);
+                    $arguments = $this->recursiveArrayHandler($state, $singleMatch['ViewHelperArguments'], $viewHelper);
                 } else {
                     $arguments = [];
                 }
@@ -563,26 +563,41 @@
         $undeclaredArguments = [];
         $matches = [];
         if (preg_match_all(Patterns::$SPLIT_PATTERN_TAGARGUMENTS, $argumentsString, $matches, PREG_SET_ORDER) > 0) {
-            $escapingEnabledBackup = $this->escapingEnabled;
-            $this->escapingEnabled = false;
             foreach ($matches as $singleMatch) {
                 $argument = $singleMatch['Argument'];
                 $value = $this->unquoteString($singleMatch['ValueQuoted']);
-                $argumentsObjectTree[$argument] = $this->buildArgumentObjectTree($value);
+                $escapingEnabledBackup = $this->escapingEnabled;
                 if (isset($argumentDefinitions[$argument])) {
                     $argumentDefinition = $argumentDefinitions[$argument];
-                    if ($argumentDefinition->getType() === 'boolean' || $argumentDefinition->getType() === 'bool') {
+                    $this->escapingEnabled = $this->escapingEnabled && $this->isArgumentEscaped($viewHelper, $argumentDefinition);
+                    $isBoolean = $argumentDefinition->getType() === 'boolean' || $argumentDefinition->getType() === 'bool';
+                    $argumentsObjectTree[$argument] = $this->buildArgumentObjectTree($value);
+                    if ($isBoolean) {
                         $argumentsObjectTree[$argument] = new BooleanNode($argumentsObjectTree[$argument]);
                     }
                 } else {
-                    $undeclaredArguments[$argument] = $argumentsObjectTree[$argument];
-                }
-            }
-            $this->escapingEnabled = $escapingEnabledBackup;
+                    $this->escapingEnabled = false;
+                    $undeclaredArguments[$argument] = $this->buildArgumentObjectTree($value);
+                }
+                $this->escapingEnabled = $escapingEnabledBackup;
+            }
         }
         $this->abortIfRequiredArgumentsAreMissing($argumentDefinitions, $argumentsObjectTree);
         $viewHelper->validateAdditionalArguments($undeclaredArguments);
         return $argumentsObjectTree + $undeclaredArguments;
+    }
+
+    protected function isArgumentEscaped(ViewHelperInterface $viewHelper, ArgumentDefinition $argumentDefinition = null)
+    {
+        $hasDefinition = $argumentDefinition instanceof ArgumentDefinition;
+        $isBoolean = $hasDefinition && ($argumentDefinition->getType() === 'boolean' || $argumentDefinition->getType() === 'bool');
+        $escapingEnabled = $this->configuration->isViewHelperArgumentEscapingEnabled();
+        $isArgumentEscaped = $hasDefinition && $argumentDefinition->getEscape() === true;
+        $isContentArgument = $hasDefinition && method_exists($viewHelper, 'resolveContentArgumentName') && $argumentDefinition->getName() === $viewHelper->resolveContentArgumentName();
+        if ($isContentArgument) {
+            return !$isBoolean && ($viewHelper->isChildrenEscapingEnabled() || $isArgumentEscaped);
+        }
+        return !$isBoolean && $escapingEnabled && $isArgumentEscaped;
     }
 
     /**
@@ -664,7 +679,7 @@
                 && preg_match(Patterns::$SCAN_PATTERN_SHORTHANDSYNTAX_ARRAYS, $section, $matchedVariables) > 0
             ) {
                 // We only match arrays if we are INSIDE viewhelper arguments
-                $this->arrayHandler($state, $this->recursiveArrayHandler($matchedVariables['Array']));
+                $this->arrayHandler($state, $this->recursiveArrayHandler($state, $matchedVariables['Array']));
             } else {
                 // We ask custom ExpressionNode instances from ViewHelperResolver
                 // if any match our expression:
@@ -737,12 +752,13 @@
      * - Variables
      * - sub-arrays
      *
+     * @param ParsingState $state
      * @param string $arrayText Array text
      * @param ViewHelperInterface|null $viewHelper ViewHelper instance - passed only if the array is a collection of arguments for an inline ViewHelper
      * @return NodeInterface[] the array node built up
      * @throws Exception
      */
-    protected function recursiveArrayHandler($arrayText, ViewHelperInterface $viewHelper = null)
+    protected function recursiveArrayHandler(ParsingState $state, $arrayText, ViewHelperInterface $viewHelper = null)
     {
         $undeclaredArguments = [];
         $argumentDefinitions = [];
@@ -755,14 +771,25 @@
             foreach ($matches as $singleMatch) {
                 $arrayKey = $this->unquoteString($singleMatch['Key']);
                 $assignInto = &$arrayToBuild;
-                if (!isset($argumentDefinitions[$arrayKey])) {
+                $isBoolean = false;
+                $argumentDefinition = null;
+                if (isset($argumentDefinitions[$arrayKey])) {
+                    $argumentDefinition = $argumentDefinitions[$arrayKey];
+                    $isBoolean = $argumentDefinitions[$arrayKey]->getType() === 'boolean' || $argumentDefinitions[$arrayKey]->getType() === 'bool';
+                } else {
                     $assignInto = &$undeclaredArguments;
                 }
 
+                $escapingEnabledBackup = $this->escapingEnabled;
+                $this->escapingEnabled = $this->escapingEnabled && $viewHelper instanceof ViewHelperInterface && $this->isArgumentEscaped($viewHelper, $argumentDefinition);
+
                 if (array_key_exists('Subarray', $singleMatch) && !empty($singleMatch['Subarray'])) {
-                    $assignInto[$arrayKey] = new ArrayNode($this->recursiveArrayHandler($singleMatch['Subarray']));
+                    $assignInto[$arrayKey] = new ArrayNode($this->recursiveArrayHandler($state, $singleMatch['Subarray']));
                 } elseif (!empty($singleMatch['VariableIdentifier'])) {
                     $assignInto[$arrayKey] = new ObjectAccessorNode($singleMatch['VariableIdentifier']);
+                    if ($viewHelper instanceof ViewHelperInterface && !$isBoolean) {
+                        $this->callInterceptor($assignInto[$arrayKey], InterceptorInterface::INTERCEPT_OBJECTACCESSOR, $state);
+                    }
                 } elseif (array_key_exists('Number', $singleMatch) && (!empty($singleMatch['Number']) || $singleMatch['Number'] === '0')) {
                     // Note: this method of casting picks "int" when value is a natural number and "float" if any decimals are found. See also NumericNode.
                     $assignInto[$arrayKey] = $singleMatch['Number'] + 0;
@@ -771,9 +798,11 @@
                     $assignInto[$arrayKey] = $this->buildArgumentObjectTree($argumentString);
                 }
 
-                if (isset($argumentDefinitions[$arrayKey]) && ($argumentDefinitions[$arrayKey]->getType() === 'boolean' || $argumentDefinitions[$arrayKey]->getType() === 'bool')) {
+                if ($isBoolean) {
                     $assignInto[$arrayKey] = new BooleanNode($assignInto[$arrayKey]);
                 }
+
+                $this->escapingEnabled = $escapingEnabledBackup;
             }
         }
         if ($viewHelper instanceof ViewHelperInterface) {
```
