# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4248_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4248_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 741-781 of the vulnerable file.

     * Check if thread is reassigned for another operator
     *
     * Updates thread info, send events messages and avatar message to user.
     *
     * @param array $operator Operator for test
     */
    public function checkForReassign($operator)
    {
        $operator_name = ($this->locale == get_home_locale())
            ? $operator['vclocalename']
            : $operator['vccommonname'];

        $is_operator_correct = $this->nextAgent == $operator['operatorid']
            || $this->agentId == $operator['operatorid'];

        if ($this->state == self::STATE_WAITING && $is_operator_correct) {
            // Prepare message
            if ($this->nextAgent == $operator['operatorid']) {
                $message_to_post = getlocal(
                    "Operator <strong>{0}</strong> changed operator <strong>{1}</strong>",
                    array($operator_name, $this->agentName),
                    $this->locale,
                    true
                );
            } else {
                $message_to_post = getlocal(
                    "Operator {0} is back",
                    array($operator_name),
                    $this->locale,
                    true
                );
            }

            // Update thread info
            $this->state = self::STATE_CHATTING;
            $this->nextAgent = 0;
            $this->agentId = $operator['operatorid'];
            $this->agentName = $operator_name;
            $this->save();

            // Send messages
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -758,14 +758,14 @@
             if ($this->nextAgent == $operator['operatorid']) {
                 $message_to_post = getlocal(
                     "Operator <strong>{0}</strong> changed operator <strong>{1}</strong>",
-                    array($operator_name, $this->agentName),
+                    array(safe_htmlspecialchars($operator_name), safe_htmlspecialchars($this->agentName)),
                     $this->locale,
                     true
                 );
             } else {
                 $message_to_post = getlocal(
                     "Operator {0} is back",
-                    array($operator_name),
+                    array(safe_htmlspecialchars($operator_name)),
                     $this->locale,
                     true
                 );
@@ -926,7 +926,7 @@
                 self::KIND_EVENTS,
                 getlocal(
                     "Visitor {0} left the chat",
-                    array($this->userName),
+                    array(safe_htmlspecialchars($this->userName)),
                     $this->locale,
                     true
                 )
@@ -947,7 +947,7 @@
                     self::KIND_EVENTS,
                     getlocal(
                         "Operator {0} left the chat",
-                        array($this->agentName),
+                        array(safe_htmlspecialchars($this->agentName)),
                         $this->locale,
                         true
                     )
@@ -1025,21 +1025,21 @@
         if ($is_operator_changed) {
             $message = getlocal(
                 "Operator <strong>{0}</strong> changed operator <strong>{1}</strong>",
-                array($operator_name, $this->agentName),
+                array(safe_htmlspecialchars($operator_name), safe_htmlspecialchars($this->agentName)),
                 $this->locale,
                 true
             );
         } elseif ($is_operator_joined) {
             $message = getlocal(
                 "Operator {0} joined the chat",
-                array($operator_name),
+                array(safe_htmlspecialchars($operator_name)),
                 $this->locale,
                 true
             );
         } elseif ($is_operator_back) {
             $message = getlocal(
                 "Operator {0} is back",
-                array($operator_name),
+                array(safe_htmlspecialchars($operator_name)),
                 $this->locale,
                 true
             );
@@ -1083,7 +1083,7 @@
             // Send message about renaming
             $message = getlocal(
                 "The visitor changed their name <strong>{0}</strong> to <strong>{1}</strong>",
-                array($old_name, $new_name),
+                array(safe_htmlspecialchars($old_name), safe_htmlspecialchars($new_name)),
                 $this->locale,
                 true
             );
```
