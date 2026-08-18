# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 5212_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5212_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 2745-2785 of the vulnerable file.

        if (newHistory == NULL) {
            return 0;
        }
        if (len < tocopy) {
            tocopy = len;
        }
        memcpy(newHistory, history + historyMaxLen - tocopy, sizeof(UChar8*) * tocopy);
        free(history);
        history = newHistory;
    }
    historyMaxLen = len;
    if (historyLen > historyMaxLen) {
        historyLen = historyMaxLen;
    }
    return 1;
}

/* Save the history in the specified file. On success 0 is returned
 * otherwise -1 is returned. */
int linenoiseHistorySave(const char* filename) {
    FILE* fp = fopen(filename, "wt");
    if (fp == NULL) {
        return -1;
    }

    for (int j = 0; j < historyLen; ++j) {
        if (history[j][0] != '\0') {
            fprintf(fp, "%s\n", history[j]);
        }
    }
    fclose(fp);
    return 0;
}

/* Load the history from the specified file. If the file does not exist
 * zero is returned and no operation is performed.
 *
 * If the file exists and the operation succeeded 0 is returned, otherwise
 * on error -1 is returned. */
int linenoiseHistoryLoad(const char* filename) {
    FILE* fp = fopen(filename, "rt");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2762,7 +2762,17 @@
 /* Save the history in the specified file. On success 0 is returned
  * otherwise -1 is returned. */
 int linenoiseHistorySave(const char* filename) {
-    FILE* fp = fopen(filename, "wt");
+    FILE* fp;
+#if _POSIX_C_SOURCE >= 1 || _XOPEN_SOURCE || _POSIX_SOURCE
+    int fd = open(filename, O_CREAT, S_IRUSR | S_IWUSR);
+    if (fd == -1) {
+        // report errno somehow?
+        return -1;
+    }
+    fp = fdopen(fd, "wt");
+#else
+    fp = fopen(filename, "wt");
+#endif  // _POSIX_C_SOURCE >= 1 || _XOPEN_SOURCE || _POSIX_SOURCE
     if (fp == NULL) {
         return -1;
     }
@@ -2772,7 +2782,7 @@
             fprintf(fp, "%s\n", history[j]);
         }
     }
-    fclose(fp);
+    fclose(fp);  // Also causes fd to be closed.
     return 0;
 }
 
```
