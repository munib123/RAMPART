# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2942_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2942_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2385-2426 of the vulnerable file.

            }
        }
        if ($this->_resources) {
            $json->rs = $this->_resources;
        }
        if ($full) {
            $json->id = $this->id;
            $json->ty = $this->calendarType;
            $json->sd = $this->start->strftime('%x');
            $json->st = $this->start->format($time_format);
            $json->ed = $this->end->strftime('%x');
            $json->et = $this->end->format($time_format);
            $json->tz = $this->timezone;
            $json->a = $this->alarm;
            $json->pv = $this->private;
            if ($this->recurs()) {
                $json->r = $this->recurrence->toJson();
            }
            if (!$this->isPrivate()) {
                $json->d = $this->description;
                $json->u = $this->url;
                $json->uhl = $GLOBALS['injector']->getInstance('Horde_Core_Factory_TextFilter')->filter($this->url, 'linkurls');
                $json->tg = array_values($this->tags);
                $json->gl = $this->geoLocation;
                if ($this->attendees) {
                    $attendees = array();
                    foreach ($this->attendees as $email => $info) {
                        $tmp = new Horde_Mail_Rfc822_Address($email);
                        if (!empty($info['name'])) {
                            $tmp->personal = $info['name'];
                        }

                        $attendees[] = array(
                            'a' => intval($info['attendance']),
                            'e' => $tmp->bare_address,
                            'r' => intval($info['response']),
                            'l' => strval($tmp)
                        );
                        $json->at = $attendees;
                    }
                }
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2402,8 +2402,8 @@
             }
             if (!$this->isPrivate()) {
                 $json->d = $this->description;
-                $json->u = $this->url;
-                $json->uhl = $GLOBALS['injector']->getInstance('Horde_Core_Factory_TextFilter')->filter($this->url, 'linkurls');
+                $json->u =  htmlentities($this->url);
+                $json->uhl = htmlentities($GLOBALS['injector']->getInstance('Horde_Core_Factory_TextFilter')->filter($this->url, 'linkurls'));
                 $json->tg = array_values($this->tags);
                 $json->gl = $this->geoLocation;
                 if ($this->attendees) {
```
