# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4454_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4454_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 35-75 of the vulnerable file.

        ));
        foreach ($template['TemplateElement'] as $k => &$element) {
            $element['position'] = $k+1;
        }
        $this->saveAll($template);
    }

    public function checkAuthorisation($id, $user, $write)
    {
        // fetch the bare template
        $template = $this->find('first', array(
            'conditions' => array('id' => $id),
            'recursive' => -1,
        ));

        // if not found return false
        if (empty($template)) {
            return false;
        }

        //if the user is a site admin, return the template withoug question
        if ($user['Role']['perm_site_admin']) {
            return $template;
        }

        if ($write) {
            // if write access is requested, check if template belongs to user's org and whether the user is authorised to edit templates
            if ($user['Organisation']['name'] == $template['Template']['org'] && $user['Role']['perm_template']) {
                return $template;
            }
            return false;
        } else {

            // if read access is requested, check if the template belongs to the user's org or alternatively whether the template is shareable
            if ($user['Organisation']['name'] == $template['Template']['org'] || $template['Template']['share']) {
                return $template;
            }
            return false;
        }
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
             return false;
         }
 
-        //if the user is a site admin, return the template withoug question
+        //if the user is a site admin, return the template without question
         if ($user['Role']['perm_site_admin']) {
             return $template;
         }
```
