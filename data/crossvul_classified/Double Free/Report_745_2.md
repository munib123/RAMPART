# CrossVul Fix Pair: Double Free in c
**Pair ID:** 745_2
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `745_2`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 141-162 of the vulnerable file.


		memcpy(tmp_paths[listNumber], pathTmp, sizeof(char)*(strlen(pathTmp)+1));
		memcpy(tmp_accts[listNumber], acctTmp, sizeof(char)*(strlen(acctTmp)+1));

		listNumber = listNumber + 1;
	}

	*paths = (char **) realloc(tmp_paths, (int)sizeof(char *)*listNumber);
	*accts = (char **) realloc(tmp_accts, (int)sizeof(char *)*listNumber);

	*list_l = listNumber;

	return NULL;
}

void freeListData(char *** data, unsigned int length) {
	int i;
	for(i=0; i<length; i++) {
		free((*data)[i]);
	}
	free(*data);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,5 +158,4 @@
 	for(i=0; i<length; i++) {
 		free((*data)[i]);
 	}
-	free(*data);
 }
```
