# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 2279_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2279_3`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 37-78 of the vulnerable file.


    plugin.state(settings.key, settings.cookieOptions);

    plugin.ext('onPostAuth', function (request, reply) {

        // Validate incoming crumb

        if (typeof request.route.plugins._crumb === 'undefined') {
            if (request.route.plugins.crumb ||
                !request.route.plugins.hasOwnProperty('crumb') && settings.autoGenerate) {

                request.route.plugins._crumb = Hoek.applyToDefaults(internals.routeDefaults, request.route.plugins.crumb || {});
            }
            else {
                request.route.plugins._crumb = false;
            }
        }

        // Set crumb cookie and calculate crumb

        if (settings.autoGenerate ||
            request.route.plugins._crumb) {

            generate(request, reply);
        }

        // Validate crumb

        if (settings.restful === false ||
            (!request.route.plugins._crumb || request.route.plugins._crumb.restful === false)) {

            if (request.method !== 'post' ||
                !request.route.plugins._crumb) {

                return reply();
            }

            var content = request[request.route.plugins._crumb.source];
            if (content instanceof Stream) {

                return reply(plugin.hapi.error.forbidden());
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,8 +54,9 @@
 
         // Set crumb cookie and calculate crumb
 
-        if (settings.autoGenerate ||
-            request.route.plugins._crumb) {
+        if ((settings.autoGenerate ||
+            request.route.plugins._crumb) &&
+            !request.headers.origin) {
 
             generate(request, reply);
         }
```
