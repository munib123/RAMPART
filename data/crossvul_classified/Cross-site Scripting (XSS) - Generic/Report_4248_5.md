# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4248_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4248_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 108-148 of the vulnerable file.

    $thread->invitationState = Thread::INVITATION_WAIT;
    $thread->save();

    $db = Database::getInstance();
    $db->query(
        ("UPDATE {sitevisitor} set "
            . "invitations = invitations + 1, "
            . "threadid = :thread_id "
            . "WHERE visitorid = :visitor_id"),
        array(
            ':thread_id' => $thread->id,
            ':visitor_id' => $visitor_id,
        )
    );

    // Send some messages
    $thread->postMessage(
        Thread::KIND_FOR_AGENT,
        getlocal(
            'Operator {0} invites visitor at {1} page',
            array($operator_name, $last_visited_page),
            get_current_locale(),
            true
        )
    );
    $thread->postMessage(
        Thread::KIND_AGENT,
        getlocal('Hello, how can I help you?', null, get_current_locale(), true),
        array(
            'name' => $operator_name,
            'operator_id' => $operator['operatorid'],
        )
    );

    // Let plugins know about the invitation.
    $args = array('invitation' => $thread);
    EventDispatcher::getInstance()->triggerEvent(Events::INVITATION_CREATE, $args);

    return $thread;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,7 +125,7 @@
         Thread::KIND_FOR_AGENT,
         getlocal(
             'Operator {0} invites visitor at {1} page',
-            array($operator_name, $last_visited_page),
+            array(safe_htmlspecialchars($operator_name), safe_htmlspecialchars($last_visited_page)),
             get_current_locale(),
             true
         )
```
