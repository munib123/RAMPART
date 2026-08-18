# CrossVul Fix Pair: Session Fixation in php
**Pair ID:** 5381_2
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5381_2`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```php
Lines 59-100 of the vulnerable file.

        $doSession = OA_Dal::staticGetDO('session', $session_id);
        if ($doSession) {
            $doSession->lastused = OA::getNowUTC();
            $doSession->update();
        }
    }

    /**
     * @param string $serialized_session_data
     * @param string $session_id
     *
     * @todo Use ANSI SQL syntax, such as an UPDATE/INSERT cycle.
     * @todo Push down REPLACE INTO into a MySQL-specific DAL.
     */
    function storeSerializedSession($serialized_session_data, $session_id)
    {
        $doSession = OA_Dal::staticGetDO('session', $session_id);
        if ($doSession) {
            $doSession->sessiondata = $serialized_session_data;
            $doSession->update();
        }
        else {
            $doSession = OA_Dal::factoryDO('session');
            $doSession->sessionid = $session_id;
            $doSession->sessiondata = $serialized_session_data;
            $doSession->insert();
        }
    }

    /**
     * Remove many unused sessions from storage.
     *
     * @todo Use ANSI SQL syntax, such as NOW() + INTERVAL '12' HOUR
     */
    function pruneOldSessions()
    {
        $tableS = $this->oDbh->quoteIdentifier( $this->getTablePrefix().'session',true);
        $query = "
                DELETE FROM {$tableS}
                WHERE
                    UNIX_TIMESTAMP('". OA::getNowUTC() ."') - UNIX_TIMESTAMP(lastused) > 43200
                ";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,10 +76,10 @@
         if ($doSession) {
             $doSession->sessiondata = $serialized_session_data;
             $doSession->update();
-        }
-        else {
+        } else {
             $doSession = OA_Dal::factoryDO('session');
-            $doSession->sessionid = $session_id;
+            // It's an md5, so 32 chars max
+            $doSession->sessionid = substr($session_id, 0, 32);
             $doSession->sessiondata = $serialized_session_data;
             $doSession->insert();
         }
```
