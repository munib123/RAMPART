# CrossVul Fix Pair: Access of Uninitialized Pointer in c
**Pair ID:** 4684_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-824
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4684_0`)

## Vulnerability Information & PoC

## Description
Access of Uninitialized Pointer - If the pointer contains an uninitialized value, then the value might not point to a valid memory location.

## Vulnerable Code
```c
Lines 76-116 of the vulnerable file.

            *z = 0;
        }
        do {
            if (fgets(dir, sizeof dir, fp) == NULL || *dir == 0) {
                goto bad;
            }
            {
                char * const z = dir + strlen(dir) - 1U;

                if (*z == '\n') {
                    *z = 0;
                }
            }
        } while (*dir == '#' || *dir == 0);
        if (head == NULL) {
            if ((head = tail = malloc(sizeof *head)) == NULL ||
                (tail->alias = strdup(alias)) == NULL ||
                (tail->dir = strdup(dir)) == NULL) {
                die_mem();
            }
            tail->next = NULL;
        } else {
            DirAlias *curr;

            if ((curr = malloc(sizeof *curr)) == NULL ||
                (curr->alias = strdup(alias)) == NULL ||
                (curr->dir = strdup(dir)) == NULL) {
                die_mem();
            }
            tail->next = curr;
            tail = curr;
        }
    }
    fclose(fp);
    aliases_up++;

    return 0;

    bad:
    fclose(fp);
    logfile(LOG_ERR, MSG_ALIASES_BROKEN_FILE " [" ALIASES_FILE "]");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,7 +93,6 @@
                 (tail->dir = strdup(dir)) == NULL) {
                 die_mem();
             }
-            tail->next = NULL;
         } else {
             DirAlias *curr;
 
@@ -105,6 +104,7 @@
             tail->next = curr;
             tail = curr;
         }
+        tail->next = NULL;
     }
     fclose(fp);
     aliases_up++;
```
