# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4248_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4248_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 164-204 of the vulnerable file.

    protected function redirectToGroup(Thread $thread, $group_id)
    {
        if ($thread->state != Thread::STATE_CHATTING) {
            // We can redirect only threads which are in proggress now.
            return false;
        }

        // Redirect the thread
        $thread->state = Thread::STATE_WAITING;
        $thread->nextAgent = 0;
        $thread->groupId = $group_id;
        $thread->agentId = 0;
        $thread->agentName = '';
        $thread->save();

        // Send notification message
        $thread->postMessage(
            Thread::KIND_EVENTS,
            getlocal(
                'Operator {0} redirected you to another operator. Please wait a while.',
                array(get_operator_name($this->getOperator())),
                $thread->locale,
                true
            )
        );

        return true;
    }

    /**
     * Redirects a chat thread to the operator with the specified ID.
     *
     * @param \Mibew\Thread $thread Chat thread to redirect.
     * @param int $group_id ID of the target operator.
     * @return boolean True if the thread was redirected and false on failure.
     */
    protected function redirectToOperator(Thread $thread, $operator_id)
    {
        if ($thread->state != Thread::STATE_CHATTING) {
            // We can redirect only threads which are in proggress now.
            return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,7 +181,7 @@
             Thread::KIND_EVENTS,
             getlocal(
                 'Operator {0} redirected you to another operator. Please wait a while.',
-                array(get_operator_name($this->getOperator())),
+                array(safe_htmlspecialchars(get_operator_name($this->getOperator()))),
                 $thread->locale,
                 true
             )
@@ -235,7 +235,7 @@
             Thread::KIND_EVENTS,
             getlocal(
                 'Operator {0} redirected you to another operator. Please wait a while.',
-                array(get_operator_name($this->getOperator())),
+                array(safe_htmlspecialchars(get_operator_name($this->getOperator()))),
                 $thread->locale,
                 true
             )
```
