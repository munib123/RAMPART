# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 1532_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1532_6`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 287-329 of the vulnerable file.

        if (!get_settings().show_advanced_options)
          return;
        var data = frameData.get(tabId, frameId);
        if (data !== undefined)
            data.resources[elType + ':|:' + url] = null;
      },

      onTabClosedHandler: function(tabId) {
        delete frameData[tabId];
      }
    };

    var normalizeRequestType = function(details) {
        // normalize type, because of issue with Chrome 38+
        var type = details.type;
        if (type !== 'other') {
            return type;
        }
        var url = parseUri(details.url);
        if (url && url.pathname) {
            var pos = url.pathname.lastIndexOf('.');
            if (pos === -1) {
                return type;
            }
        }
        var ext = url.pathname.slice(pos) + '.';
        if ('.eot.ttf.otf.svg.woff.woff2.'.indexOf(ext) !== -1) {
            return 'font';
        }
        // Still need this because often behind-the-scene requests are wrongly
        // categorized as 'other'
        if ('.ico.png.gif.jpg.jpeg.webp.'.indexOf(ext) !== -1) {
            return 'image';
        }
        // https://code.google.com/p/chromium/issues/detail?id=410382
        if (type === 'other') {
            return 'object';
        }
    };

    // When a request starts, perhaps block it.
    function onBeforeRequestHandler(details) {
      if (adblock_is_paused())
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -304,24 +304,21 @@
         }
         var url = parseUri(details.url);
         if (url && url.pathname) {
-            var pos = url.pathname.lastIndexOf('.');
-            if (pos === -1) {
-                return type;
+          var pos = url.pathname.lastIndexOf('.');
+          if (pos > -1) {
+            var ext = url.pathname.slice(pos) + '.';
+            if ('.eot.ttf.otf.svg.woff.woff2.'.indexOf(ext) !== -1) {
+              return 'font';
             }
-        }
-        var ext = url.pathname.slice(pos) + '.';
-        if ('.eot.ttf.otf.svg.woff.woff2.'.indexOf(ext) !== -1) {
-            return 'font';
-        }
-        // Still need this because often behind-the-scene requests are wrongly
-        // categorized as 'other'
-        if ('.ico.png.gif.jpg.jpeg.webp.'.indexOf(ext) !== -1) {
-            return 'image';
-        }
-        // https://code.google.com/p/chromium/issues/detail?id=410382
-        if (type === 'other') {
-            return 'object';
-        }
+            // Still need this because often behind-the-scene requests are wrongly
+            // categorized as 'other'
+            if ('.ico.png.gif.jpg.jpeg.webp.'.indexOf(ext) !== -1) {
+              return 'image';
+            }
+          }
+        }
+        // see crbug.com/410382
+        return 'object';
     };
 
     // When a request starts, perhaps block it.
@@ -1336,8 +1333,10 @@
       var subscribed_filter_names = [];
       var get_subscriptions = get_subscriptions_minus_text();
       for (var id in get_subscriptions) {
-          if (get_subscriptions[id].subscribed)
+          if (get_subscriptions[id].subscribed) {
               subscribed_filter_names.push(id);
+              subscribed_filter_names.push("  last updated: " + new Date(get_subscriptions[id].last_update).toUTCString());
+          }
       }
 
       // Get last known error
@@ -1354,6 +1353,9 @@
       var settings = get_settings();
       for (setting in settings)
           adblock_settings.push(setting + ": "+ get_settings()[setting] + "\n");
+      // We need to hardcode malware-notification setting,
+      // because it isn't included in _settings object, but just in localStorage
+      adblock_settings.push("malware-notification: " + storage_get('malware-notification') + "\n");
       adblock_settings = adblock_settings.join('');
 
       // Create debug info for a bug report or an ad report
```
