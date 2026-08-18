# CrossVul Fix Pair: Origin Validation Error in php
**Pair ID:** 3134_0
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3134_0`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```php
Lines 1-45 of the vulnerable file.

<?php
/*
 * @file Carbons.php
 *
 * @brief Handle incoming carbons messages
 *
 * Copyright 2014 edhelas <edhelas@edhelas-laptop>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 *
 */

namespace Moxl\Xec\Payload;

class Carbons extends Payload
{
    public function handle($stanza, $parent = false)
    {
        $message = $stanza->forwarded->message;

        $jid = explode('/',(string)$message->attributes()->from);
        $to = current(explode('/',(string)$message->attributes()->to));

        if($message->composing)
            $this->event('composing', array($jid[0], $to));
        if($message->paused)
            $this->event('paused', array($jid[0], $to));
        if($message->gone)
            $this->event('gone', array($jid[0], $to));

        if($message->body || $message->subject) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,28 +1,4 @@
 <?php
-/*
- * @file Carbons.php
- *
- * @brief Handle incoming carbons messages
- *
- * Copyright 2014 edhelas <edhelas@edhelas-laptop>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License as published by
- * the Free Software Foundation; either version 2 of the License, or
- * (at your option) any later version.
- *
- * This program is distributed in the hope that it will be useful,
- * but WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
- * GNU General Public License for more details.
- *
- * You should have received a copy of the GNU General Public License
- * along with this program; if not, write to the Free Software
- * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
- * MA 02110-1301, USA.
- *
- *
- */
 
 namespace Moxl\Xec\Payload;
 
@@ -30,28 +6,33 @@
 {
     public function handle($stanza, $parent = false)
     {
+        $parentfrom = current(explode('/', (string)$parent->attributes()->from));
+
         $message = $stanza->forwarded->message;
 
-        $jid = explode('/',(string)$message->attributes()->from);
+        $from = current(explode('/',(string)$message->attributes()->from));
         $to = current(explode('/',(string)$message->attributes()->to));
 
-        if($message->composing)
-            $this->event('composing', array($jid[0], $to));
-        if($message->paused)
-            $this->event('paused', array($jid[0], $to));
-        if($message->gone)
-            $this->event('gone', array($jid[0], $to));
+        $user = new \User;
+        if($parentfrom == $user->getLogin()) {
+            if($message->composing)
+                $this->event('composing', [$from, $to]);
+            if($message->paused)
+                $this->event('paused', [$from, $to]);
+            if($message->gone)
+                $this->event('gone', [$from, $to]);
 
-        if($message->body || $message->subject) {
-            $m = new \Modl\Message;
-            $m->set($message, $stanza->forwarded);
+            if($message->body || $message->subject) {
+                $m = new \Modl\Message;
+                $m->set($message, $stanza->forwarded);
 
-            if(!preg_match('#^\?OTR#', $m->body)) {
-                $md = new \Modl\MessageDAO;
-                $md->set($m);
+                if(!preg_match('#^\?OTR#', $m->body)) {
+                    $md = new \Modl\MessageDAO;
+                    $md->set($m);
 
-                $this->pack($m);
-                $this->deliver();
+                    $this->pack($m);
+                    $this->deliver();
+                }
             }
         }
     }
```
