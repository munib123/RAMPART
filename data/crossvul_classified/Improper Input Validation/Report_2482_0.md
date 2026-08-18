# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 2482_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2482_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 156-196 of the vulnerable file.

 * <pre>
 *    scheme    = $2
 *    authority = $4
 *    path      = $5
 *    query     = $7
 *    fragment  = $9
 * </pre>
 *
 * The regular expression has been modified slightly to expose the
 * userInfo, domain, and port separately from the authority.
 * The modified version yields
 * <pre>
 *    $1 = http              scheme
 *    $2 = <undefined>       userInfo -\
 *    $3 = www.ics.uci.edu   domain     | authority
 *    $4 = <undefined>       port     -/
 *    $5 = /pub/ietf/uri/    path
 *    $6 = <undefined>       query without ?
 *    $7 = Related           fragment without #
 * </pre>
 * @type {!RegExp}
 * @private
 */
goog.uri.utils.splitRe_ = new RegExp(
    '^' +
    '(?:' +
    '([^:/?#.]+)' +  // scheme - ignore special characters
                     // used by other URL parts such as :,
                     // ?, /, #, and .
    ':)?' +
    '(?://' +
    '(?:([^/?#]*)@)?' +  // userInfo
    '([^/#?]*?)' +       // domain
    '(?::([0-9]+))?' +   // port
    '(?=[/\\\\#?]|$)' +  // authority-terminating character
    ')?' +
    '([^?#]+)?' +          // path
    '(?:\\?([^#]*))?' +    // query
    '(?:#([\\s\\S]*))?' +  // fragment
    '$');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -173,25 +173,31 @@
  *    $6 = <undefined>       query without ?
  *    $7 = Related           fragment without #
  * </pre>
+ *
+ * TODO(user): separate out the authority terminating characters once this
+ * file is moved to ES6.
  * @type {!RegExp}
  * @private
  */
 goog.uri.utils.splitRe_ = new RegExp(
-    '^' +
+    '^' +  // Anchor against the entire string.
     '(?:' +
     '([^:/?#.]+)' +  // scheme - ignore special characters
                      // used by other URL parts such as :,
                      // ?, /, #, and .
     ':)?' +
     '(?://' +
-    '(?:([^/?#]*)@)?' +  // userInfo
-    '([^/#?]*?)' +       // domain
-    '(?::([0-9]+))?' +   // port
-    '(?=[/\\\\#?]|$)' +  // authority-terminating character
+    '(?:([^\\\\/?#]*)@)?' +  // userInfo
+    '([^\\\\/?#]*?)' +       // domain
+    '(?::([0-9]+))?' +       // port
+    '(?=[\\\\/?#]|$)' +      // authority-terminating character.
     ')?' +
     '([^?#]+)?' +          // path
     '(?:\\?([^#]*))?' +    // query
-    '(?:#([\\s\\S]*))?' +  // fragment
+    '(?:#([\\s\\S]*))?' +  // fragment. Can't use '.*' with 's' flag as Firefox
+                           // doesn't support the flag, and can't use an
+                           // "everything set" ([^]) as IE10 doesn't match any
+                           // characters with it.
     '$');
 
 
```
