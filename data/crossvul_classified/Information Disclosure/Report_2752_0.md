# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2752_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2752_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 411-451 of the vulnerable file.

     */
    (void) AcpiNsCheckReturnValue (Info->Node, Info, Info->ParamCount,
        Status, &Info->ReturnObject);

    /* Check if there is a return value that must be dealt with */

    if (Status == AE_CTRL_RETURN_VALUE)
    {
        /* If caller does not want the return value, delete it */

        if (Info->Flags & ACPI_IGNORE_RETURN_VALUE)
        {
            AcpiUtRemoveReference (Info->ReturnObject);
            Info->ReturnObject = NULL;
        }

        /* Map AE_CTRL_RETURN_VALUE to AE_OK, we are done with it */

        Status = AE_OK;
    }

    ACPI_DEBUG_PRINT ((ACPI_DB_NAMES,
        "*** Completed evaluation of object %s ***\n",
        Info->RelativePathname));

Cleanup:
    /*
     * Namespace was unlocked by the handling AcpiNs* function, so we
     * just free the pathname and return
     */
    ACPI_FREE (Info->FullPathname);
    Info->FullPathname = NULL;
    return_ACPI_STATUS (Status);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiNsExecModuleCodeList
 *
 * PARAMETERS:  None
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -428,6 +428,16 @@
 
         Status = AE_OK;
     }
+    else if (ACPI_FAILURE(Status)) 
+    {
+        /* If ReturnObject exists, delete it */
+
+        if (Info->ReturnObject) 
+        {
+            AcpiUtRemoveReference (Info->ReturnObject);
+            Info->ReturnObject = NULL;
+        }
+    }
 
     ACPI_DEBUG_PRINT ((ACPI_DB_NAMES,
         "*** Completed evaluation of object %s ***\n",
```
