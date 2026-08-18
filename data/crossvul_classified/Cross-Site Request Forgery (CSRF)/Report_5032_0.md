# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5032_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5032_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 380-420 of the vulnerable file.

                    $this->rc->output->command('managesieve_updatelist', 'setact',
                        array('name' => $script_name, 'active' => false));
                } else {
                    $this->rc->output->show_message('managesieve.setdeactivateerror', 'error');
                }
            }
            else if ($action == 'setdel' && !$error) {
                $script_name = rcube_utils::get_input_value('_set', rcube_utils::INPUT_POST, true);
                $result = $this->remove_script($script_name);

                if ($result === true) {
                    $this->rc->output->show_message('managesieve.setdeleted', 'confirmation');
                    $this->rc->output->command('managesieve_updatelist', 'setdel',
                        array('name' => $script_name));
                    $this->rc->session->remove('managesieve_current');
                } else {
                    $this->rc->output->show_message('managesieve.setdeleteerror', 'error');
                }
            }
            else if ($action == 'setget') {
                $script_name = rcube_utils::get_input_value('_set', rcube_utils::INPUT_GPC, true);
                $script      = $this->sieve->get_script($script_name);

                if (is_a($script, 'PEAR_Error')) {
                    exit;
                }

                $browser = new rcube_browser;

                // send download headers
                header("Content-Type: application/octet-stream");
                header("Content-Length: ".strlen($script));

                if ($browser->ie) {
                    header("Content-Type: application/force-download");
                    $filename = rawurlencode($script_name);
                }
                else {
                    $filename = addcslashes($script_name, '\\"');
                }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -397,6 +397,8 @@
                 }
             }
             else if ($action == 'setget') {
+                $this->rc->request_security_check(rcube_utils::INPUT_GET);
+
                 $script_name = rcube_utils::get_input_value('_set', rcube_utils::INPUT_GPC, true);
                 $script      = $this->sieve->get_script($script_name);
 
```
