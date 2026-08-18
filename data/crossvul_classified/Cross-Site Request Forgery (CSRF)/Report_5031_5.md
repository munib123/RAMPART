# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5031_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5031_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 46-86 of the vulnerable file.

        $this->register_action('plugin.zipdownload.messages', array($this, 'download_messages'));

        if (!$rcmail->action && $rcmail->config->get('zipdownload_selection')) {
            $this->download_menu();
        }
    }

    /**
     * Place a link/button after attachments listing to trigger download
     */
    public function attachment_ziplink($p)
    {
        $rcmail = rcmail::get_instance();

        // only show the link if there is more than the configured number of attachments
        if (substr_count($p['content'], '<li') > $rcmail->config->get('zipdownload_attachments', 1)) {
            $href = $rcmail->url(array(
                '_action' => 'plugin.zipdownload.attachments',
                '_mbox'   => $rcmail->output->env['mailbox'],
                '_uid'    => $rcmail->output->env['uid'],
            ));

            $link = html::a(array('href' => $href, 'class' => 'button zipdownload'),
                rcube::Q($this->gettext('downloadall'))
            );

            // append link to attachments list, slightly different in some skins
            switch (rcmail::get_instance()->config->get('skin')) {
                case 'classic':
                    $p['content'] = str_replace('</ul>', html::tag('li', array('class' => 'zipdownload'), $link) . '</ul>', $p['content']);
                    break;

                default:
                    $p['content'] .= $link;
                    break;
            }

            $this->include_stylesheet($this->local_skin_path() . '/zipdownload.css');
        }

        return $p;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,7 +63,7 @@
                 '_action' => 'plugin.zipdownload.attachments',
                 '_mbox'   => $rcmail->output->env['mailbox'],
                 '_uid'    => $rcmail->output->env['uid'],
-            ));
+            ), false, false, true);
 
             $link = html::a(array('href' => $href, 'class' => 'button zipdownload'),
                 rcube::Q($this->gettext('downloadall'))
@@ -120,6 +120,10 @@
     public function download_attachments()
     {
         $rcmail    = rcmail::get_instance();
+
+        // require CSRF protected request
+        $rcmail->request_security_check(rcube_utils::INPUT_GET);
+
         $imap      = $rcmail->get_storage();
         $temp_dir  = $rcmail->config->get('temp_dir');
         $tmpfname  = tempnam($temp_dir, 'zipdownload');
```
