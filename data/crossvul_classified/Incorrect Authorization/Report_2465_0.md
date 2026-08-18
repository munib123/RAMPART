# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 2465_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2465_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 36-76 of the vulnerable file.

     * @param string                    $strategy                           The vote strategy
     * @param bool                      $allowIfAllAbstainDecisions         Whether to grant access if all voters abstained or not
     * @param bool                      $allowIfEqualGrantedDeniedDecisions Whether to grant access if result are equals
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(iterable $voters = [], string $strategy = self::STRATEGY_AFFIRMATIVE, bool $allowIfAllAbstainDecisions = false, bool $allowIfEqualGrantedDeniedDecisions = true)
    {
        $strategyMethod = 'decide'.ucfirst($strategy);
        if ('' === $strategy || !\is_callable([$this, $strategyMethod])) {
            throw new \InvalidArgumentException(sprintf('The strategy "%s" is not supported.', $strategy));
        }

        $this->voters = $voters;
        $this->strategy = $strategyMethod;
        $this->allowIfAllAbstainDecisions = $allowIfAllAbstainDecisions;
        $this->allowIfEqualGrantedDeniedDecisions = $allowIfEqualGrantedDeniedDecisions;
    }

    /**
     * {@inheritdoc}
     */
    public function decide(TokenInterface $token, array $attributes, $object = null)
    {
        if (\count($attributes) > 1) {
            @trigger_error(sprintf('Passing more than one Security attribute to "%s()" is deprecated since Symfony 4.4. Use multiple "decide()" calls or the expression language (e.g. "is_granted(...) or is_granted(...)") instead.', __METHOD__), E_USER_DEPRECATED);
        }

        return $this->{$this->strategy}($token, $attributes, $object);
    }

    /**
     * Grants access if any voter returns an affirmative response.
     *
     * If all voters abstained from voting, the decision will be based on the
     * allowIfAllAbstainDecisions property value (defaults to false).
     */
    private function decideAffirmative(TokenInterface $token, array $attributes, $object = null): bool
    {
        $deny = 0;
        foreach ($this->voters as $voter) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,11 +53,16 @@
     }
 
     /**
+     * @param bool $allowMultipleAttributes Whether to allow passing multiple values to the $attributes array
+     *
      * {@inheritdoc}
      */
-    public function decide(TokenInterface $token, array $attributes, $object = null)
+    public function decide(TokenInterface $token, array $attributes, $object = null/*, bool $allowMultipleAttributes = false*/)
     {
-        if (\count($attributes) > 1) {
+        $allowMultipleAttributes =  3 < func_num_args() && func_get_arg(3);
+
+        // Special case for AccessListener, do not remove the right side of the condition before 6.0
+        if (\count($attributes) > 1 && !$allowMultipleAttributes) {
             @trigger_error(sprintf('Passing more than one Security attribute to "%s()" is deprecated since Symfony 4.4. Use multiple "decide()" calls or the expression language (e.g. "is_granted(...) or is_granted(...)") instead.', __METHOD__), E_USER_DEPRECATED);
         }
 
```
