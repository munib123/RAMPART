# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4248_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4248_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 33-73 of the vulnerable file.

     * Returns content of the chat button.
     *
     * @param Request $request
     * @return string Rendered page content
     */
    public function indexAction(Request $request)
    {
        $referer = $request->server->get('HTTP_REFERER', '');

        // We need to display message about visited page only if the visitor
        // really change it.
        $new_page = empty($_SESSION[SESSION_PREFIX . 'last_visited_page'])
            || $_SESSION[SESSION_PREFIX . 'last_visited_page'] != $referer;

        // Display message about page change
        if ($referer && isset($_SESSION[SESSION_PREFIX . 'threadid']) && $new_page) {
            $thread = Thread::load($_SESSION[SESSION_PREFIX . 'threadid']);
            if ($thread && $thread->state != Thread::STATE_CLOSED) {
                $msg = getlocal(
                    "Visitor navigated to {0}",
                    array($referer),
                    $thread->locale,
                    true
                );
                $thread->postMessage(Thread::KIND_FOR_AGENT, $msg);
            }
        }
        $_SESSION[SESSION_PREFIX . 'last_visited_page'] = $referer;

        $image = $request->query->get('i', '');
        if (!preg_match("/^\w+$/", $image)) {
            $image = 'mibew';
        }

        $lang = $request->query->get('lang', '');
        if (!preg_match("/^[\w-]{2,5}$/", $lang)) {
            $lang = '';
        }
        if (!$lang || !locale_is_available($lang)) {
            $lang = get_current_locale();
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,7 +50,7 @@
             if ($thread && $thread->state != Thread::STATE_CLOSED) {
                 $msg = getlocal(
                     "Visitor navigated to {0}",
-                    array($referer),
+                    array(safe_htmlspecialchars($referer)),
                     $thread->locale,
                     true
                 );
```
