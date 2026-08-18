# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5032_7
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5032_7`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 88-131 of the vulnerable file.

        $this->storage->set_options(array('all_headers' => true));

        // Set current folder
        $this->storage->set_folder($this->folder);

        $this->headers = $this->storage->get_message($uid);

        if (!$this->headers) {
            return;
        }

        $this->mime = new rcube_mime($this->headers->charset);

        $this->subject = $this->headers->get('subject');
        list(, $this->sender) = each($this->mime->decode_address_list($this->headers->from, 1));

        $this->set_safe((intval($_GET['_safe']) || $_SESSION['safe_messages'][$this->folder.':'.$uid]));
        $this->opt = array(
            'safe' => $this->is_safe,
            'prefer_html' => $this->app->config->get('prefer_html'),
            'get_url' => $this->app->url(array(
                'action' => 'get',
                'mbox'   => $this->storage->get_folder(),
                'uid'    => $uid))
        );

        if (!empty($this->headers->structure)) {
            $this->get_mime_numbers($this->headers->structure);
            $this->parse_structure($this->headers->structure);
        }
        else {
            $this->body = $this->storage->get_body($uid);
        }

        // notify plugins and let them analyze this structured message object
        $this->app->plugins->exec_hook('message_load', array('object' => $this));
    }


    /**
     * Return a (decoded) message header
     *
     * @param string $name Header name
     * @param bool   $row  Don't mime-decode the value
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,10 +105,11 @@
         $this->opt = array(
             'safe' => $this->is_safe,
             'prefer_html' => $this->app->config->get('prefer_html'),
-            'get_url' => $this->app->url(array(
-                'action' => 'get',
-                'mbox'   => $this->storage->get_folder(),
-                'uid'    => $uid))
+            'get_url'     => $this->app->url(array(
+                    'action' => 'get',
+                    'mbox'   => $this->storage->get_folder(),
+                    'uid'    => $uid),
+                false, false, true)
         );
 
         if (!empty($this->headers->structure)) {
```
