# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5031_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5031_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 442-482 of the vulnerable file.

            }
            $username .= ' <' . $user->email . '>';

            $table->add('id', rcube::Q(trim($username)));
            $table->add('valid', $this->enigma->gettext($user->valid ? 'valid' : 'unknown'));
            $table->set_row_attribs($user->revoked || !$user->valid ? 'deleted' : '');
        }

        $out .= html::tag('fieldset', null,
            html::tag('legend', null,
                $this->enigma->gettext('userids')) . $table->show());

        return $out;
    }

    /**
     * Key(s) export handler
     */
    private function key_export()
    {
        $keys   = rcube_utils::get_input_value('_keys', rcube_utils::INPUT_GPC);
        $engine = $this->enigma->load_engine();
        $list   = $keys == '*' ? $engine->list_keys() : explode(',', $keys);

        if (is_array($list)) {
            $filename = 'export.pgp';
            if (count($list) == 1) {
                $filename = (is_object($list[0]) ? $list[0]->id : $list[0]) . '.pgp';
            }

            // send downlaod headers
            header('Content-Type: application/pgp-keys');
            header('Content-Disposition: attachment; filename="' . $filename . '"');

            if ($fp = fopen('php://output', 'w')) {
                foreach ($list as $key) {
                    $engine->export_key(is_object($key) ? $key->id : $key, $fp);
                }
            }
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -459,6 +459,8 @@
      */
     private function key_export()
     {
+        $this->rc->request_security_check(rcube_utils::INPUT_GET);
+
         $keys   = rcube_utils::get_input_value('_keys', rcube_utils::INPUT_GPC);
         $engine = $this->enigma->load_engine();
         $list   = $keys == '*' ? $engine->list_keys() : explode(',', $keys);
```
