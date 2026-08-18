# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4286_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4286_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 95-135 of the vulnerable file.

      ret = rtJsonEncIntValue (pJsonCtxt, value);
#endif
      if (0 != ret) return LOG_RTERR (pJsonCtxt, ret);
      break;
   }
   case OSRTCBOR_BYTESTR: {
      OSDynOctStr64 byteStr;
      ret = rtCborDecDynByteStr (pCborCtxt, ub, &byteStr);
      if (0 != ret) return LOG_RTERR (pCborCtxt, ret);

      /* Encode JSON */
      ret = rtJsonEncHexStr (pJsonCtxt, byteStr.numocts, byteStr.data);
      rtxMemFreePtr (pCborCtxt, byteStr.data);
      if (0 != ret) return LOG_RTERR (pJsonCtxt, ret);

      break;
   }
   case OSRTCBOR_UTF8STR: {
      OSUTF8CHAR* utf8str;
      ret = rtCborDecDynUTF8Str (pCborCtxt, ub, (char**)&utf8str);

      ret = rtJsonEncStringValue (pJsonCtxt, utf8str);
      rtxMemFreePtr (pCborCtxt, utf8str);
      if (0 != ret) return LOG_RTERR (pJsonCtxt, ret);

      break;
   }
   case OSRTCBOR_ARRAY: 
   case OSRTCBOR_MAP: {
      OSOCTET len = ub & 0x1F;
      char startChar = (tag == OSRTCBOR_ARRAY) ? '[' : '{';
      char endChar = (tag == OSRTCBOR_ARRAY) ? ']' : '}';

      OSRTSAFEPUTCHAR (pJsonCtxt, startChar);

      if (len == OSRTCBOR_INDEF) {
         OSBOOL first = TRUE;
         for (;;) {
            if (OSRTCBOR_MATCHEOC (pCborCtxt)) {
               pCborCtxt->buffer.byteIndex++;
               break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -112,6 +112,7 @@
    case OSRTCBOR_UTF8STR: {
       OSUTF8CHAR* utf8str;
       ret = rtCborDecDynUTF8Str (pCborCtxt, ub, (char**)&utf8str);
+      if (0 != ret) return LOG_RTERR (pCborCtxt, ret);
 
       ret = rtJsonEncStringValue (pJsonCtxt, utf8str);
       rtxMemFreePtr (pCborCtxt, utf8str);
```
