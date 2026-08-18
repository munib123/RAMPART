# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 1946_6
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1946_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 976-1016 of the vulnerable file.

                    value = $re(/^([+-]?\d*\.?\d+)(%|[a-z]+)?/);
                    if (value) {
                        return new(tree.Dimension)(value[1], value[2]);
                    }
                },

                //
                // A unicode descriptor, as is used in unicode-range
                //
                // U+0??  or U+00A1-00A9
                //
                unicodeDescriptor: function () {
                    var ud;

                    ud = $re(/^U\+[0-9a-fA-F?]+(\-[0-9a-fA-F?]+)?/);
                    if (ud) {
                        return new(tree.UnicodeDescriptor)(ud[0]);
                    }
                },

                //
                // JavaScript code to be evaluated
                //
                //     `window.location.href`
                //
                javascript: function () {
                    var str, j = i, e;

                    if (input.charAt(j) === '~') { j++; e = true; } // Escaped strings
                    if (input.charAt(j) !== '`') { return; }
                    if (env.javascriptEnabled !== undefined && !env.javascriptEnabled) {
                        error("You are using JavaScript, which has been disabled.");
                    }

                    if (e) { $char('~'); }

                    str = $re(/^`([^`]*)`/);
                    if (str) {
                        return new(tree.JavaScript)(str[1], i, e);
                    }
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -993,27 +993,23 @@
                     }
                 },
 
-                //
-                // JavaScript code to be evaluated
+                /* BEGIN MODIFICATION */
+                // Removed support for javascript
+
+                //
+                // JavaScript code (disabled)
                 //
                 //     `window.location.href`
                 //
                 javascript: function () {
-                    var str, j = i, e;
+                    var j = i, e;
 
                     if (input.charAt(j) === '~') { j++; e = true; } // Escaped strings
                     if (input.charAt(j) !== '`') { return; }
-                    if (env.javascriptEnabled !== undefined && !env.javascriptEnabled) {
-                        error("You are using JavaScript, which has been disabled.");
-                    }
-
-                    if (e) { $char('~'); }
-
-                    str = $re(/^`([^`]*)`/);
-                    if (str) {
-                        return new(tree.JavaScript)(str[1], i, e);
-                    }
-                }
+
+                    error("You are using JavaScript, which has been disabled.");
+                }
+                /* END MODIFICATION */
             },
 
             //
```
