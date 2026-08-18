# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1178_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1178_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 900-940 of the vulnerable file.

    if ( 1 != readresult ) {
        Mat_VarFree(matvar);
        return NULL;
    }
    if ( mat->byteswap )
        Mat_int32Swap(&tmp);
    /* Check that the length of the variable name is at least 1 */
    if ( tmp < 1 ) {
        Mat_VarFree(matvar);
        return NULL;
    }
    matvar->name = (char*)malloc(tmp);
    if ( NULL == matvar->name ) {
        Mat_VarFree(matvar);
        return NULL;
    }
    readresult = fread(matvar->name,1,tmp,(FILE*)mat->fp);
    if ( tmp != readresult ) {
        Mat_VarFree(matvar);
        return NULL;
    }

    matvar->internal->datapos = ftell((FILE*)mat->fp);
    if ( matvar->internal->datapos == -1L ) {
        Mat_VarFree(matvar);
        Mat_Critical("Couldn't determine file position");
        return NULL;
    }
    {
        int err;
        size_t tmp2 = Mat_SizeOf(matvar->data_type);
        if ( matvar->isComplex )
            tmp2 *= 2;
        err = SafeMulDims(matvar, &tmp2);
        if ( err ) {
            Mat_VarFree(matvar);
            Mat_Critical("Integer multiplication overflow");
            return NULL;
        }

        nBytes = (long)tmp2;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -917,6 +917,8 @@
     if ( tmp != readresult ) {
         Mat_VarFree(matvar);
         return NULL;
+    } else {
+        matvar->name[tmp - 1] = '\0';
     }
 
     matvar->internal->datapos = ftell((FILE*)mat->fp);
```
