# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2751_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2751_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 751-791 of the vulnerable file.

 *
 * FUNCTION:    AcpiPsCompleteFinalOp
 *
 * PARAMETERS:  WalkState           - Current state
 *              Op                  - Current Op
 *              Status              - Current parse status before complete last
 *                                    Op
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Complete last Op.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiPsCompleteFinalOp (
    ACPI_WALK_STATE         *WalkState,
    ACPI_PARSE_OBJECT       *Op,
    ACPI_STATUS             Status)
{
    ACPI_STATUS             Status2;


    ACPI_FUNCTION_TRACE_PTR (PsCompleteFinalOp, WalkState);


    /*
     * Complete the last Op (if not completed), and clear the scope stack.
     * It is easily possible to end an AML "package" with an unbounded number
     * of open scopes (such as when several ASL blocks are closed with
     * sequential closing braces). We want to terminate each one cleanly.
     */
    ACPI_DEBUG_PRINT ((ACPI_DB_PARSE, "AML package complete at Op %p\n", Op));
    do
    {
        if (Op)
        {
            if (WalkState->AscendingCallback != NULL)
            {
                WalkState->Op = Op;
                WalkState->OpInfo = AcpiPsGetOpcodeInfo (Op->Common.AmlOpcode);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -768,7 +768,8 @@
     ACPI_PARSE_OBJECT       *Op,
     ACPI_STATUS             Status)
 {
-    ACPI_STATUS             Status2;
+    ACPI_STATUS             ReturnStatus = AE_OK;
+    BOOLEAN                 Ascending = TRUE;
 
 
     ACPI_FUNCTION_TRACE_PTR (PsCompleteFinalOp, WalkState);
@@ -785,7 +786,7 @@
     {
         if (Op)
         {
-            if (WalkState->AscendingCallback != NULL)
+            if (Ascending && WalkState->AscendingCallback != NULL)
             {
                 WalkState->Op = Op;
                 WalkState->OpInfo = AcpiPsGetOpcodeInfo (Op->Common.AmlOpcode);
@@ -804,41 +805,28 @@
 
                 if (Status == AE_CTRL_TERMINATE)
                 {
-                    Status = AE_OK;
-
-                    /* Clean up */
-                    do
-                    {
-                        if (Op)
-                        {
-                            Status2 = AcpiPsCompleteThisOp (WalkState, Op);
-                            if (ACPI_FAILURE (Status2))
-                            {
-                                return_ACPI_STATUS (Status2);
-                            }
-                        }
-
-                        AcpiPsPopScope (&(WalkState->ParserState), &Op,
-                            &WalkState->ArgTypes, &WalkState->ArgCount);
-
-                    } while (Op);
-
-                    return_ACPI_STATUS (Status);
+                    Ascending = FALSE;
+                    ReturnStatus = AE_CTRL_TERMINATE;
                 }
 
                 else if (ACPI_FAILURE (Status))
                 {
                     /* First error is most important */
 
-                    (void) AcpiPsCompleteThisOp (WalkState, Op);
-                    return_ACPI_STATUS (Status);
+                    Ascending = FALSE;
+                    ReturnStatus = Status;
                 }
             }
 
-            Status2 = AcpiPsCompleteThisOp (WalkState, Op);
-            if (ACPI_FAILURE (Status2))
+            Status = AcpiPsCompleteThisOp (WalkState, Op);
+            if (ACPI_FAILURE (Status))
             {
-                return_ACPI_STATUS (Status2);
+                Ascending = FALSE;
+                if (ACPI_SUCCESS (ReturnStatus) ||
+                    ReturnStatus == AE_CTRL_TERMINATE)
+                {
+                    ReturnStatus = Status;
+                }
             }
         }
 
@@ -847,5 +835,5 @@
 
     } while (Op);
 
-    return_ACPI_STATUS (Status);
+    return_ACPI_STATUS (ReturnStatus);
 }
```
