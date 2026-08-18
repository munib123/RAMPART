# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4248_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4248_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 654-694 of the vulnerable file.

            return array(
                'next' => 'leaveMessage',
                'options' => $options,
            );
        }

        // Initialize dialog
        $thread = chat_start_for_user(
            $group_id,
            false,
            $visitor['id'],
            $visitor['name'],
            $referrer,
            $info
        );

        // Send some messages
        if ($email) {
            $thread->postMessage(
                Thread::KIND_FOR_AGENT,
                getlocal('E-Mail: {0}', array($email), get_current_locale(), true)
            );
        }

        if ($first_message) {
            $posted_id = $thread->postMessage(
                Thread::KIND_USER,
                $first_message,
                array('name' => $visitor['name'])
            );
            $thread->shownMessageId = $posted_id;
            $thread->save();
        }

        // Prepare chat options
        $client_data = setup_chatview_for_user(
            $this->getRouter(),
            $this->getAssetManager()->getUrlGenerator(),
            $this->currentRequest,
            $thread
        );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -671,7 +671,7 @@
         if ($email) {
             $thread->postMessage(
                 Thread::KIND_FOR_AGENT,
-                getlocal('E-Mail: {0}', array($email), get_current_locale(), true)
+                getlocal('E-Mail: {0}', array(safe_htmlspecialchars($email)), get_current_locale(), true)
             );
         }
 
@@ -790,19 +790,19 @@
         if ($referrer) {
             $thread->postMessage(
                 Thread::KIND_FOR_AGENT,
-                getlocal('Visitor came from page {0}', array($referrer), get_current_locale(), true)
+                getlocal('Visitor came from page {0}', array(safe_htmlspecialchars($referrer)), get_current_locale(), true)
             );
         }
         if ($email) {
             $thread->postMessage(
                 Thread::KIND_FOR_AGENT,
-                getlocal('E-Mail: {0}', array($email), get_current_locale(), true)
+                getlocal('E-Mail: {0}', array(safe_htmlspecialchars($email)), get_current_locale(), true)
             );
         }
         if ($info) {
             $thread->postMessage(
                 Thread::KIND_FOR_AGENT,
-                getlocal('Info: {0}', array($info), get_current_locale(), true)
+                getlocal('Info: {0}', array(safe_htmlspecialchars($info)), get_current_locale(), true)
             );
         }
         $thread->postMessage(Thread::KIND_USER, $message, array('name' => $name));
```
