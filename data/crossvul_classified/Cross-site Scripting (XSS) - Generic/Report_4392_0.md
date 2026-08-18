# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4392_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4392_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 369-409 of the vulnerable file.

      if (!graphviz) throw Error('viz.js output empty graph')
      $value.html(graphviz)

      $ele.addClass('graphviz')
      $value.children().unwrap().unwrap()
    } catch (err) {
      $value.unwrap()
      $value.parent().append(`<div class="alert alert-warning">${escapeHTML(err)}</div>`)
      console.warn(err)
    }
  })
  // mermaid
  const mermaids = view.find('div.mermaid.raw').removeClass('raw')
  mermaids.each((key, value) => {
    try {
      var $value = $(value)
      const $ele = $(value).closest('pre')

      window.mermaid.mermaidAPI.parse($value.text())
      $ele.addClass('mermaid')
      $ele.html($value.text())
      window.mermaid.init(undefined, $ele)
    } catch (err) {
      var errormessage = err
      if (err.str) {
        errormessage = err.str
      }

      $value.unwrap()
      $value.parent().append(`<div class="alert alert-warning">${escapeHTML(errormessage)}</div>`)
      console.warn(errormessage)
    }
  })
  // abc.js
  const abcs = view.find('div.abc.raw').removeClass('raw')
  abcs.each((key, value) => {
    try {
      var $value = $(value)
      var $ele = $(value).parent().parent()

      window.ABCJS.renderAbc(value, $value.text())
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -386,7 +386,7 @@
 
       window.mermaid.mermaidAPI.parse($value.text())
       $ele.addClass('mermaid')
-      $ele.html($value.text())
+      $ele.text($value.text())
       window.mermaid.init(undefined, $ele)
     } catch (err) {
       var errormessage = err
```
