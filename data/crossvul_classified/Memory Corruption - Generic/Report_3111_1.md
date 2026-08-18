# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3111_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3111_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 71-111 of the vulnerable file.

  sprintf(szTmp, "%s", "(\"[");
  szTmp[4] = '\0';

  strlcat(szBuffer, szTmp, bufferSize);

  /* attribute */
  strlcat(szBuffer, psFilterNode->psLeftNode->pszValue, bufferSize);
  szBuffer[strlen(szBuffer)] = '\0';

  /* #3521 */
  if (bCaseInsensitive == 1)
    sprintf(szTmp, "%s", "]\" ~* \"");
  else
    sprintf(szTmp, "%s", "]\" ~ \"");
  szTmp[7] = '\0';
  strlcat(szBuffer, szTmp, bufferSize);
  szBuffer[strlen(szBuffer)] = '\0';

  pszValue = psFilterNode->psRightNode->pszValue;
  nLength = strlen(pszValue);

  iTmp =0;
  if (nLength > 0 && pszValue[0] != pszWild[0] && pszValue[0] != pszSingle[0] && pszValue[0] != pszEscape[0]) {
    szTmp[iTmp]= '^';
    iTmp++;
  }
  for (i=0; i<nLength; i++) {
    if (pszValue[i] != pszWild[0] && pszValue[i] != pszSingle[0] && pszValue[i] != pszEscape[0]) {
      szTmp[iTmp] = pszValue[i];
      iTmp++;
      szTmp[iTmp] = '\0';
    } else if (pszValue[i] == pszSingle[0]) {
      szTmp[iTmp] = '.';
      iTmp++;
      szTmp[iTmp] = '\0';
    } else if (pszValue[i] == pszEscape[0]) {
      szTmp[iTmp] = '\\';
      iTmp++;
      szTmp[iTmp] = '\0';
    } else if (pszValue[i] == pszWild[0]) {
      szTmp[iTmp++] = '.';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,6 +88,8 @@
 
   pszValue = psFilterNode->psRightNode->pszValue;
   nLength = strlen(pszValue);
+  if( 1 + 2 * nLength + 1 + 1 >= sizeof(szTmp) )
+      return NULL;
 
   iTmp =0;
   if (nLength > 0 && pszValue[0] != pszWild[0] && pszValue[0] != pszSingle[0] && pszValue[0] != pszEscape[0]) {
```
