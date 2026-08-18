# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 160_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `160_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 162-202 of the vulnerable file.

      result[0]='G';
      itostr(pin-JSH_PORTG_OFFSET,&result[1],10);
#endif
#if JSH_PORTH_OFFSET!=-1
    } else if (pin>=JSH_PORTH_OFFSET && pin<JSH_PORTH_OFFSET+JSH_PORTH_COUNT) {
      result[0]='H';
      itostr(pin-JSH_PORTH_OFFSET,&result[1],10);
#endif
#if JSH_PORTI_OFFSET!=-1
    } else if (pin>=JSH_PORTI_OFFSET && pin<JSH_PORTI_OFFSET+JSH_PORTI_COUNT) {
      result[0]='I';
      itostr(pin-JSH_PORTI_OFFSET,&result[1],10);
#endif
#if JSH_PORTV_OFFSET!=-1
    } else if (pin>=JSH_PORTV_OFFSET && pin<JSH_PORTV_OFFSET+JSH_PORTV_COUNT) {
      result[0]='V';
      itostr(pin-JSH_PORTV_OFFSET,&result[1],10);
#endif
#endif
    } else {
      strncpy(result, "undefined", 10);
    }
  }

/**
 * Given a var, convert it to a pin ID (or PIN_UNDEFINED if it doesn't exist). safe for undefined!
 */
Pin jshGetPinFromVar(
    JsVar *pinv //!< The class instance representing a Pin.
  ) {
  if (jsvIsString(pinv) && pinv->varData.str[5]==0/*should never be more than 4 chars!*/) {
    return jshGetPinFromString(&pinv->varData.str[0]);
  } else if (jsvIsInt(pinv) /* This also tests for the Pin datatype */) {
    return (Pin)jsvGetInteger(pinv);
  } else return PIN_UNDEFINED;
}

Pin jshGetPinFromVarAndUnLock(JsVar *pinv) {
  Pin pin = jshGetPinFromVar(pinv);
  jsvUnLock(pinv);
  return pin;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -179,7 +179,7 @@
 #endif
 #endif
     } else {
-      strncpy(result, "undefined", 10);
+      strcpy(result, "undefined");
     }
   }
 
@@ -379,10 +379,10 @@
     jsiConsolePrintf("Couldn't convert pin function %d\n", pinFunc);
     return;
   }
-  if (flags & JSPFTS_DEVICE) strncat(buf, devStr, bufSize);
+  if (flags & JSPFTS_DEVICE) strncat(buf, devStr, bufSize-1);
   if (flags & JSPFTS_DEVICE_NUMBER) itostr(devIdx, &buf[strlen(buf)], 10);
-  if (flags & JSPFTS_SPACE) strncat(buf, " ", bufSize);
-  if (infoStr && (flags & JSPFTS_TYPE)) strncat(buf, infoStr, bufSize);
+  if (flags & JSPFTS_SPACE) strncat(buf, " ", bufSize-(strlen(buf)+1));
+  if (infoStr && (flags & JSPFTS_TYPE)) strncat(buf, infoStr, bufSize-(strlen(buf)+1));
 }
 
 /** Prints a list of capable pins, eg:
```
