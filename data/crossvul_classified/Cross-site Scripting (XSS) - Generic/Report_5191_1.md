# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 5191_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5191_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 687-727 of the vulnerable file.

    window.onload = function() {
      hideAll(getElementsByClassName(document, 'table', 'vars'));
      hideAll(getElementsByClassName(document, 'ol', 'pre-context'));
      hideAll(getElementsByClassName(document, 'ol', 'post-context'));
      hideAll(getElementsByClassName(document, 'div', 'pastebin'));
    }
    function toggle() {
      for (var i = 0; i < arguments.length; i++) {
        var e = document.getElementById(arguments[i]);
        if (e) {
          e.style.display = e.style.display == 'none' ? 'block': 'none';
        }
      }
      return false;
    }
    function varToggle(link, id) {
      toggle('v' + id);
      var s = link.getElementsByTagName('span')[0];
      var uarr = String.fromCharCode(0x25b6);
      var darr = String.fromCharCode(0x25bc);
      s.innerHTML = s.innerHTML == uarr ? darr : uarr;
      return false;
    }
    function switchPastebinFriendly(link) {
      s1 = "Switch to copy-and-paste view";
      s2 = "Switch back to interactive view";
      link.innerHTML = link.innerHTML.trim() == s1 ? s2: s1;
      toggle('browserTraceback', 'pastebinTraceback');
      return false;
    }
    //-->
  </script>
  {% endif %}
</head>
<body>
<div id="summary">
  <h1>{% if exception_type %}{{ exception_type }}{% else %}Report{% endif %}"""
  """{% if request %} at {{ request.path_info|escape }}{% endif %}</h1>
  <pre class="exception_value">"""
 """{% if exception_value %}{{ exception_value|force_escape }}{% else %}No exception message supplied{% endif %}"""
"""</pre>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -704,13 +704,13 @@
       var s = link.getElementsByTagName('span')[0];
       var uarr = String.fromCharCode(0x25b6);
       var darr = String.fromCharCode(0x25bc);
-      s.innerHTML = s.innerHTML == uarr ? darr : uarr;
+      s.textContent = s.textContent == uarr ? darr : uarr;
       return false;
     }
     function switchPastebinFriendly(link) {
       s1 = "Switch to copy-and-paste view";
       s2 = "Switch back to interactive view";
-      link.innerHTML = link.innerHTML.trim() == s1 ? s2: s1;
+      link.textContent = link.textContent.trim() == s1 ? s2: s1;
       toggle('browserTraceback', 'pastebinTraceback');
       return false;
     }
```
