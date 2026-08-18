# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4518_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4518_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 1170-1210 of the vulnerable file.


        return true;
    }

    /**
     * Check customer information and return customer validity.
     *
     * @since 1.5.0
     *
     * @param bool $withGuest
     *
     * @return bool customer validity
     */
    public function isLogged($withGuest = false)
    {
        if (!$withGuest && $this->is_guest == 1) {
            return false;
        }

        /* Customer is valid only if it can be load and if object password is the same as database one */
        return $this->logged == 1 && $this->id && Validate::isUnsignedId($this->id) && Customer::checkPassword($this->id, $this->passwd);
    }

    /**
     * Logout.
     *
     * @since 1.5.0
     */
    public function logout()
    {
        Hook::exec('actionCustomerLogoutBefore', array('customer' => $this));

        if (isset(Context::getContext()->cookie)) {
            Context::getContext()->cookie->logout();
        }

        $this->logged = 0;

        Hook::exec('actionCustomerLogoutAfter', array('customer' => $this));
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1187,7 +1187,13 @@
         }
 
         /* Customer is valid only if it can be load and if object password is the same as database one */
-        return $this->logged == 1 && $this->id && Validate::isUnsignedId($this->id) && Customer::checkPassword($this->id, $this->passwd);
+        return
+            $this->logged == 1
+            && $this->id
+            && Validate::isUnsignedId($this->id)
+            && Customer::checkPassword($this->id, $this->passwd)
+            && Context::getContext()->cookie->isSessionAlive()
+        ;
     }
 
     /**
```
