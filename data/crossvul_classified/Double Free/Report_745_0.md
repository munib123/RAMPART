# CrossVul Fix Pair: Double Free in c
**Pair ID:** 745_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `745_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 207-228 of the vulnerable file.


        char * path = CFStringToCharArr(str);
        char * acct = CFStringToCharArr(acctTmp);

        //We now have all we need, username and servername. Now export this to .go
        (*paths)[i] = (char *) malloc(sizeof(char)*(strlen(path)+1));
        memcpy((*paths)[i], path, sizeof(char)*(strlen(path)+1));
        (*accts)[i] = (char *) malloc(sizeof(char)*(strlen(acct)+1));
        memcpy((*accts)[i], acct, sizeof(char)*(strlen(acct)+1));

        CFRelease(str);
    }
    *list_l = (int)numKeys;
    return NULL;
}

void freeListData(char *** data, unsigned int length) {
     for(int i=0; i<length; i++) {
        free((*data)[i]);
     }
     free(*data);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,5 +224,4 @@
      for(int i=0; i<length; i++) {
         free((*data)[i]);
      }
-     free(*data);
-}
+}
```
