# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 988_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `988_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 107-147 of the vulnerable file.

        }
        session()->forget('rules.create.fromStore');

        return view(
            'rules.rule.create', compact('subTitleIcon', 'oldTriggers', 'preFilled', 'oldActions', 'triggerCount', 'actionCount', 'ruleGroup', 'subTitle')
        );
    }

    /**
     * Create a new rule. It will be stored under the given $ruleGroup.
     *
     * @param Request $request
     * @param Bill    $bill
     *
     * @return \Illuminate\Contracts\View\Factory|\Illuminate\View\View
     * @SuppressWarnings(PHPMD.ExcessiveMethodLength)
     * @SuppressWarnings(PHPMD.CyclomaticComplexity)
     */
    public function createFromBill(Request $request, Bill $bill)
    {
        $request->session()->flash('info', (string)trans('firefly.instructions_rule_from_bill', ['name' => $bill->name]));

        $this->createDefaultRuleGroup();
        $this->createDefaultRule();
        $preFilled = [
            'strict'      => true,
            'title'       => (string)trans('firefly.new_rule_for_bill_title', ['name' => $bill->name]),
            'description' => (string)trans('firefly.new_rule_for_bill_description', ['name' => $bill->name]),
        ];

        // make triggers and actions from the bill itself.

        // get triggers and actions for bill:
        $oldTriggers = $this->getTriggersForBill($bill);
        $oldActions  = $this->getActionsForBill($bill);

        $triggerCount = \count($oldTriggers);
        $actionCount  = \count($oldActions);
        $subTitleIcon = 'fa-clone';

        // title depends on whether or not there is a rule group:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -124,7 +124,7 @@
      */
     public function createFromBill(Request $request, Bill $bill)
     {
-        $request->session()->flash('info', (string)trans('firefly.instructions_rule_from_bill', ['name' => $bill->name]));
+        $request->session()->flash('info', (string)trans('firefly.instructions_rule_from_bill', ['name' => e($bill->name)]));
 
         $this->createDefaultRuleGroup();
         $this->createDefaultRule();
```
