# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in php
**Pair ID:** 2927_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2927_1`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```php
Lines 113-153 of the vulnerable file.

                return new Listener\SnippetListener(
                    $app['asset.queues'],
                    $app['canonical'],
                    $app['asset.packages'],
                    $app['config']
                );
            }
        );

        $app['listener.template_view'] = $app->share(
            function ($app) {
                return new Listener\TemplateViewListener($app['twig']);
            }
        );

        $app['listener.zone_guesser'] = $app->share(
            function ($app) {
                return new Listener\ZoneGuesser($app);
            }
        );
    }

    public function boot(Application $app)
    {
        /** @var EventDispatcherInterface $dispatcher */
        $dispatcher = $app['dispatcher'];

        $listeners = [
            'general',
            'disable_xss_protection',
            'exception_json',
            'not_found',
            'system_logger',
            'snippet',
            'redirect',
            'flash_logger',
            'template_view',
            'zone_guesser',
            'pager',
        ];

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -130,6 +130,16 @@
                 return new Listener\ZoneGuesser($app);
             }
         );
+
+        $app['listener.profile'] = $app->share(
+            function ($app) {
+                return new Listener\ProfilerListener(
+                    $app['session'],
+                    $app['debug'],
+                    $app['config']->get('general/debug_show_loggedoff')
+                );
+            }
+        );
     }
 
     public function boot(Application $app)
@@ -160,5 +170,7 @@
         if (isset($app['listener.exception']) && !$app['config']->get('general/debug_error_use_symfony')) {
             $dispatcher->addSubscriber($app['listener.exception']);
         }
+
+        $dispatcher->addSubscriber($app['listener.profile']);
     }
 }
```
