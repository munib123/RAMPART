# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 4182_3
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4182_3`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```php
Lines 608-648 of the vulnerable file.

                // We ask custom ExpressionNode instances from ViewHelperResolver
                // if any match our expression:
                foreach ($this->renderingContext->getExpressionNodeTypes() as $expressionNodeTypeClassName) {
                    $detectionExpression = $expressionNodeTypeClassName::$detectionExpression;
                    $matchedVariables = [];
                    preg_match_all($detectionExpression, $section, $matchedVariables, PREG_SET_ORDER);
                    if (is_array($matchedVariables) === true) {
                        foreach ($matchedVariables as $matchedVariableSet) {
                            $expressionStartPosition = strpos($section, $matchedVariableSet[0]);
                            /** @var ExpressionNodeInterface $expressionNode */
                            $expressionNode = new $expressionNodeTypeClassName($matchedVariableSet[0], $matchedVariableSet, $state);
                            try {
                                // Trigger initial parse-time evaluation to allow the node to manipulate the rendering context.
                                if ($expressionNode instanceof ParseTimeEvaluatedExpressionNodeInterface) {
                                    $expressionNode->evaluate($this->renderingContext);
                                }

                                if ($expressionStartPosition > 0) {
                                    $state->getNodeFromStack()->addChildNode(new TextNode(substr($section, 0, $expressionStartPosition)));
                                }
                                $state->getNodeFromStack()->addChildNode($expressionNode);

                                $expressionEndPosition = $expressionStartPosition + strlen($matchedVariableSet[0]);
                                if ($expressionEndPosition < strlen($section)) {
                                    $this->textAndShorthandSyntaxHandler($state, substr($section, $expressionEndPosition), $context);
                                    break;
                                }
                            } catch (ExpressionException $error) {
                                $this->textHandler(
                                    $state,
                                    $this->renderingContext->getErrorHandler()->handleExpressionError($error)
                                );
                            }
                        }
                    }
                }

                if (!$expressionNode) {
                    // As fallback we simply render the expression back as template content.
                    $this->textHandler($state, $section);
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -625,6 +625,8 @@
                                 if ($expressionStartPosition > 0) {
                                     $state->getNodeFromStack()->addChildNode(new TextNode(substr($section, 0, $expressionStartPosition)));
                                 }
+
+                                $this->callInterceptor($expressionNode, InterceptorInterface::INTERCEPT_EXPRESSION, $state);
                                 $state->getNodeFromStack()->addChildNode($expressionNode);
 
                                 $expressionEndPosition = $expressionStartPosition + strlen($matchedVariableSet[0]);
```
