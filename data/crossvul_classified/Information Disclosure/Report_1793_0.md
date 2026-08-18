# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1793_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1793_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 47-87 of the vulnerable file.

	  if (*objp == NULL)
	       size = 0;
	  else
	       size = strlen(*objp) + 1;
     }
     if (! xdr_u_int(xdrs, &size)) {
	  return FALSE;
	}
     switch (xdrs->x_op) {
     case XDR_DECODE:
	  if (size == 0) {
	       *objp = NULL;
	       return TRUE;
	  } else if (*objp == NULL) {
	       *objp = (char *) mem_alloc(size);
	       if (*objp == NULL) {
		    errno = ENOMEM;
		    return FALSE;
	       }
	  }
	  return (xdr_opaque(xdrs, *objp, size));

     case XDR_ENCODE:
	  if (size != 0)
	       return (xdr_opaque(xdrs, *objp, size));
	  return TRUE;

     case XDR_FREE:
	  if (*objp != NULL)
	       mem_free(*objp, size);
	  *objp = NULL;
	  return TRUE;
     }

     return FALSE;
}

/*
 * Function: xdr_nulltype
 *
 * Purpose: XDR function for arbitrary pointer types that are either
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,7 +64,14 @@
 		    return FALSE;
 	       }
 	  }
-	  return (xdr_opaque(xdrs, *objp, size));
+	  if (!xdr_opaque(xdrs, *objp, size))
+		  return FALSE;
+	  /* Check that the unmarshalled bytes are a C string. */
+	  if ((*objp)[size - 1] != '\0')
+		  return FALSE;
+	  if (memchr(*objp, '\0', size - 1) != NULL)
+		  return FALSE;
+	  return TRUE;
 
      case XDR_ENCODE:
 	  if (size != 0)
```
