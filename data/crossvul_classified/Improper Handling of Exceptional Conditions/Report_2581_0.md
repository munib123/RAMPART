# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in c
**Pair ID:** 2581_0
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2581_0`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```c
Lines 749-789 of the vulnerable file.

}


/*******************************************************************************
 *
 * FUNCTION:    AcpiNsTerminate
 *
 * PARAMETERS:  none
 *
 * RETURN:      none
 *
 * DESCRIPTION: free memory allocated for namespace and ACPI table storage.
 *
 ******************************************************************************/

void
AcpiNsTerminate (
    void)
{
    ACPI_STATUS             Status;


    ACPI_FUNCTION_TRACE (NsTerminate);


#ifdef ACPI_EXEC_APP
    {
        ACPI_OPERAND_OBJECT     *Prev;
        ACPI_OPERAND_OBJECT     *Next;

        /* Delete any module-level code blocks */

        Next = AcpiGbl_ModuleCodeList;
        while (Next)
        {
            Prev = Next;
            Next = Next->Method.Mutex;
            Prev->Method.Mutex = NULL; /* Clear the Mutex (cheated) field */
            AcpiUtRemoveReference (Prev);
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -766,28 +766,23 @@
     void)
 {
     ACPI_STATUS             Status;
+    ACPI_OPERAND_OBJECT     *Prev;
+    ACPI_OPERAND_OBJECT     *Next;
 
 
     ACPI_FUNCTION_TRACE (NsTerminate);
 
 
-#ifdef ACPI_EXEC_APP
-    {
-        ACPI_OPERAND_OBJECT     *Prev;
-        ACPI_OPERAND_OBJECT     *Next;
-
-        /* Delete any module-level code blocks */
-
-        Next = AcpiGbl_ModuleCodeList;
-        while (Next)
-        {
-            Prev = Next;
-            Next = Next->Method.Mutex;
-            Prev->Method.Mutex = NULL; /* Clear the Mutex (cheated) field */
-            AcpiUtRemoveReference (Prev);
-        }
-    }
-#endif
+    /* Delete any module-level code blocks */
+
+    Next = AcpiGbl_ModuleCodeList;
+    while (Next)
+    {
+        Prev = Next;
+        Next = Next->Method.Mutex;
+        Prev->Method.Mutex = NULL; /* Clear the Mutex (cheated) field */
+        AcpiUtRemoveReference (Prev);
+    }
 
     /*
      * Free the entire namespace -- all nodes and all objects
```
