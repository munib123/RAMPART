# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4404_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4404_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 657-697 of the vulnerable file.

    }

    /* Check if tagname contains Unicode */
    if (stringMatch(currentNode.nodeName, /[\u0080-\uFFFF]/)) {
      _forceRemove(currentNode);
      return true;
    }

    /* Now let's check the element's type and name */
    const tagName = stringToLowerCase(currentNode.nodeName);

    /* Execute a hook if present */
    _executeHook('uponSanitizeElement', currentNode, {
      tagName,
      allowedTags: ALLOWED_TAGS,
    });

    /* Take care of an mXSS pattern using p, br inside svg, math */
    if (
      (tagName === 'svg' || tagName === 'math') &&
      currentNode.querySelectorAll('p, br, form').length !== 0
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Remove element if anything forbids its presence */
    if (!ALLOWED_TAGS[tagName] || FORBID_TAGS[tagName]) {
      /* Keep content except for bad-listed elements */
      if (
        KEEP_CONTENT &&
        !FORBID_CONTENTS[tagName] &&
        typeof currentNode.insertAdjacentHTML === 'function'
      ) {
        try {
          const htmlToInsert = currentNode.innerHTML;
          currentNode.insertAdjacentHTML(
            'AfterEnd',
            trustedTypesPolicy
              ? trustedTypesPolicy.createHTML(htmlToInsert)
              : htmlToInsert
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -674,7 +674,7 @@
     /* Take care of an mXSS pattern using p, br inside svg, math */
     if (
       (tagName === 'svg' || tagName === 'math') &&
-      currentNode.querySelectorAll('p, br, form').length !== 0
+      currentNode.querySelectorAll('p, br, form, table').length !== 0
     ) {
       _forceRemove(currentNode);
       return true;
```
