# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4518_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4518_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 463-504 of the vulnerable file.

            if ($this->passwd != $passwd) {
                $this->passwd = $crypto->hash($passwd);
            }
        } else {
            $this->passwd = $crypto->hash($passwd);
        }

        return true;
    }

    /**
     * Check employee informations saved into cookie and return employee validity.
     *
     * @return bool employee validity
     */
    public function isLoggedBack()
    {
        if (!Cache::isStored('isLoggedBack' . $this->id)) {
            /* Employee is valid only if it can be load and if cookie password is the same as database one */
            $result = (
                $this->id && Validate::isUnsignedId($this->id) && Context::getContext()->cookie && Employee::checkPassword($this->id, Context::getContext()->cookie->passwd)
                    && (!isset(Context::getContext()->cookie->remote_addr) || Context::getContext()->cookie->remote_addr == ip2long(Tools::getRemoteAddr()) || !Configuration::get('PS_COOKIE_CHECKIP'))
            );
            Cache::store('isLoggedBack' . $this->id, $result);

            return $result;
        }

        return Cache::retrieve('isLoggedBack' . $this->id);
    }

    /**
     * Logout.
     */
    public function logout()
    {
        if (isset(Context::getContext()->cookie)) {
            Context::getContext()->cookie->logout();
            Context::getContext()->cookie->write();
        }
        $this->id = null;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -480,8 +480,16 @@
         if (!Cache::isStored('isLoggedBack' . $this->id)) {
             /* Employee is valid only if it can be load and if cookie password is the same as database one */
             $result = (
-                $this->id && Validate::isUnsignedId($this->id) && Context::getContext()->cookie && Employee::checkPassword($this->id, Context::getContext()->cookie->passwd)
-                    && (!isset(Context::getContext()->cookie->remote_addr) || Context::getContext()->cookie->remote_addr == ip2long(Tools::getRemoteAddr()) || !Configuration::get('PS_COOKIE_CHECKIP'))
+                $this->id
+                && Validate::isUnsignedId($this->id)
+                && Context::getContext()->cookie
+                && Context::getContext()->cookie->isSessionAlive()
+                && Employee::checkPassword($this->id, Context::getContext()->cookie->passwd)
+                && (
+                    !isset(Context::getContext()->cookie->remote_addr)
+                    || Context::getContext()->cookie->remote_addr == ip2long(Tools::getRemoteAddr())
+                    || !Configuration::get('PS_COOKIE_CHECKIP')
+                )
             );
             Cache::store('isLoggedBack' . $this->id, $result);
 
@@ -500,6 +508,7 @@
             Context::getContext()->cookie->logout();
             Context::getContext()->cookie->write();
         }
+
         $this->id = null;
     }
 
```
