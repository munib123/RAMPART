# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4248_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4248_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 680-720 of the vulnerable file.


    // Store own thread ids to restrict access for other people
    if (!isset($_SESSION[SESSION_PREFIX . 'own_threads'])) {
        $_SESSION[SESSION_PREFIX . 'own_threads'] = array();
    }
    $_SESSION[SESSION_PREFIX . 'own_threads'][] = $thread->id;

    // Bind thread to the visitor
    if (Settings::get('enabletracking')) {
        track_visitor_bind_thread($visitor_id, $thread);
    }

    // Send several messages
    if ($is_invited) {
        $operator = operator_by_id($thread->agentId);
        $operator_name = get_operator_name($operator);
        $thread->postMessage(
            Thread::KIND_FOR_AGENT,
            getlocal(
                'Visitor accepted invitation from operator {0}',
                array($operator_name),
                get_current_locale(),
                true
            )
        );
    } else {
        if ($referrer) {
            $thread->postMessage(
                Thread::KIND_FOR_AGENT,
                getlocal('Visitor came from page {0}', array($referrer), get_current_locale(), true)
            );
        }
        if ($requested_operator && !$requested_operator_online) {
            $thread->postMessage(
                Thread::KIND_INFO,
                getlocal(
                    'Thank you for contacting us. We are sorry, but requested operator <strong>{0}</strong> is offline. Another operator will be with you shortly.',
                    array(get_operator_name($requested_operator)),
                    get_current_locale(),
                    true
                )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -697,7 +697,7 @@
             Thread::KIND_FOR_AGENT,
             getlocal(
                 'Visitor accepted invitation from operator {0}',
-                array($operator_name),
+                array(safe_htmlspecialchars($operator_name)),
                 get_current_locale(),
                 true
             )
@@ -706,7 +706,7 @@
         if ($referrer) {
             $thread->postMessage(
                 Thread::KIND_FOR_AGENT,
-                getlocal('Visitor came from page {0}', array($referrer), get_current_locale(), true)
+                getlocal('Visitor came from page {0}', array(safe_htmlspecialchars($referrer)), get_current_locale(), true)
             );
         }
         if ($requested_operator && !$requested_operator_online) {
@@ -714,7 +714,7 @@
                 Thread::KIND_INFO,
                 getlocal(
                     'Thank you for contacting us. We are sorry, but requested operator <strong>{0}</strong> is offline. Another operator will be with you shortly.',
-                    array(get_operator_name($requested_operator)),
+                    array(safe_htmlspecialchars(get_operator_name($requested_operator))),
                     get_current_locale(),
                     true
                 )
@@ -731,7 +731,7 @@
     if ($info) {
         $thread->postMessage(
             Thread::KIND_FOR_AGENT,
-            getlocal('Info: {0}', array($info), get_current_locale(), true)
+            getlocal('Info: {0}', array(safe_htmlspecialchars($info)), get_current_locale(), true)
         );
     }
 
```
