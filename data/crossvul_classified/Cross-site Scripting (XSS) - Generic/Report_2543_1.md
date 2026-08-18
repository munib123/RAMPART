# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2543_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2543_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 127-167 of the vulnerable file.

                                <?php echo format_currency($client->client_invoice_balance); ?>
                            </td>
                        </tr>
                    </table>

                </div>
            </div>

            <hr>

            <div class="row">
                <div class="col-xs-12 col-md-6">

                    <div class="panel panel-default no-margin">
                        <div class="panel-heading"><?php _trans('contact_information'); ?></div>
                        <div class="panel-body table-content">
                            <table class="table no-margin">
                                <?php if ($client->client_email) : ?>
                                    <tr>
                                        <th><?php _trans('email'); ?></th>
                                        <td><?php echo auto_link($client->client_email, 'email'); ?></td>
                                    </tr>
                                <?php endif; ?>
                                <?php if ($client->client_phone) : ?>
                                    <tr>
                                        <th><?php _trans('phone'); ?></th>
                                        <td><?php _htmlsc($client->client_phone); ?></td>
                                    </tr>
                                <?php endif; ?>
                                <?php if ($client->client_mobile) : ?>
                                    <tr>
                                        <th><?php _trans('mobile'); ?></th>
                                        <td><?php _htmlsc($client->client_mobile); ?></td>
                                    </tr>
                                <?php endif; ?>
                                <?php if ($client->client_fax) : ?>
                                    <tr>
                                        <th><?php _trans('fax'); ?></th>
                                        <td><?php _htmlsc($client->client_fax); ?></td>
                                    </tr>
                                <?php endif; ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,7 +144,7 @@
                                 <?php if ($client->client_email) : ?>
                                     <tr>
                                         <th><?php _trans('email'); ?></th>
-                                        <td><?php echo auto_link($client->client_email, 'email'); ?></td>
+                                        <td><?php _auto_link($client->client_email, 'email'); ?></td>
                                     </tr>
                                 <?php endif; ?>
                                 <?php if ($client->client_phone) : ?>
@@ -168,7 +168,7 @@
                                 <?php if ($client->client_web) : ?>
                                     <tr>
                                         <th><?php _trans('web'); ?></th>
-                                        <td><?php echo auto_link($client->client_web, 'url', true); ?></td>
+                                        <td><?php _auto_link($client->client_web, 'url', true); ?></td>
                                     </tr>
                                 <?php endif; ?>
 
```
