# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3409_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3409_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 2314-2354 of the vulnerable file.

    limited_methods = apr_pstrmemdup(cmd->temp_pool, arg, endp - arg);

    if (!limited_methods[0]) {
        return missing_container_arg(cmd);
    }

    while (limited_methods[0]) {
        char *method = ap_getword_conf(cmd->temp_pool, &limited_methods);
        int methnum;

        /* check for builtin or module registered method number */
        methnum = ap_method_number_of(method);

        if (methnum == M_TRACE && !tog) {
            return "TRACE cannot be controlled by <Limit>, see TraceEnable";
        }
        else if (methnum == M_INVALID) {
            /* method has not been registered yet, but resource restriction
             * is always checked before method handling, so register it.
             */
            methnum = ap_method_register(cmd->pool,
                                         apr_pstrdup(cmd->pool, method));
        }

        limited |= (AP_METHOD_BIT << methnum);
    }

    /* Killing two features with one function,
     * if (tog == NULL) <Limit>, else <LimitExcept>
     */
    limited = tog ? ~limited : limited;

    if (!(old_limited & limited)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive excludes all methods", NULL);
    }
    else if ((old_limited & limited) == old_limited) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive specifies methods already excluded",
                           NULL);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2331,6 +2331,12 @@
             /* method has not been registered yet, but resource restriction
              * is always checked before method handling, so register it.
              */
+            if (cmd->pool == cmd->temp_pool) {
+                /* In .htaccess, we can't globally register new methods. */
+                return apr_psprintf(cmd->pool, "Could not register method '%s' "
+                                   "for %s from .htaccess configuration",
+                                    method, cmd->cmd->name);
+            }
             methnum = ap_method_register(cmd->pool,
                                          apr_pstrdup(cmd->pool, method));
         }
```
