# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in c
**Pair ID:** 4043_0
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4043_0`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```c
Lines 357-389 of the vulnerable file.

#else
            tac_timeout = atoi(*argv + 8);
#endif
            if (tac_timeout == LONG_MAX) {
                _pam_log(LOG_ERR, "timeout parameter cannot be parsed as integer: %s", *argv);
                tac_timeout = 0;
            } else {
                tac_readtimeout_enable = 1;
            }
        } else {
            _pam_log(LOG_WARNING, "unrecognized option: %s", *argv);
        }
    }

    if (ctrl & PAM_TAC_DEBUG) {
        unsigned long n;

        _pam_log(LOG_DEBUG, "%d servers defined", tac_srv_no);

        for (n = 0; n < tac_srv_no; n++) {
            _pam_log(LOG_DEBUG, "server[%lu] { addr=%s, key='%s' }", n, tac_ntop(tac_srv[n].addr->ai_addr),
                     tac_srv[n].key);
        }

        _pam_log(LOG_DEBUG, "tac_service='%s'", tac_service);
        _pam_log(LOG_DEBUG, "tac_protocol='%s'", tac_protocol);
        _pam_log(LOG_DEBUG, "tac_prompt='%s'", tac_prompt);
        _pam_log(LOG_DEBUG, "tac_login='%s'", tac_login);
    }

    return ctrl;
}    /* _pam_parse */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -374,8 +374,8 @@
         _pam_log(LOG_DEBUG, "%d servers defined", tac_srv_no);
 
         for (n = 0; n < tac_srv_no; n++) {
-            _pam_log(LOG_DEBUG, "server[%lu] { addr=%s, key='%s' }", n, tac_ntop(tac_srv[n].addr->ai_addr),
-                     tac_srv[n].key);
+            _pam_log(LOG_DEBUG, "server[%lu] { addr=%s, key='********' }", n,
+			    tac_ntop(tac_srv[n].addr->ai_addr));
         }
 
         _pam_log(LOG_DEBUG, "tac_service='%s'", tac_service);
```
