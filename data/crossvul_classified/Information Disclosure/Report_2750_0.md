# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2750_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2750_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 851-891 of the vulnerable file.

 *              FirstArg            - First argument of a parser argument tree
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an operator's arguments from a parse tree format to
 *              namespace objects and place those argument object on the object
 *              stack in preparation for evaluation by the interpreter.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiDsCreateOperands (
    ACPI_WALK_STATE         *WalkState,
    ACPI_PARSE_OBJECT       *FirstArg)
{
    ACPI_STATUS             Status = AE_OK;
    ACPI_PARSE_OBJECT       *Arg;
    ACPI_PARSE_OBJECT       *Arguments[ACPI_OBJ_NUM_OPERANDS];
    UINT32                  ArgCount = 0;
    UINT32                  Index = WalkState->NumOperands;
    UINT32                  i;


    ACPI_FUNCTION_TRACE_PTR (DsCreateOperands, FirstArg);


    /* Get all arguments in the list */

    Arg = FirstArg;
    while (Arg)
    {
        if (Index >= ACPI_OBJ_NUM_OPERANDS)
        {
            return_ACPI_STATUS (AE_BAD_DATA);
        }

        Arguments[Index] = Arg;
        WalkState->Operands [Index] = NULL;

        /* Move on to next argument, if any */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -868,6 +868,8 @@
     ACPI_PARSE_OBJECT       *Arguments[ACPI_OBJ_NUM_OPERANDS];
     UINT32                  ArgCount = 0;
     UINT32                  Index = WalkState->NumOperands;
+    UINT32                  PrevNumOperands = WalkState->NumOperands;
+    UINT32                  NewNumOperands;
     UINT32                  i;
 
 
@@ -900,6 +902,7 @@
 
     /* Create the interpreter arguments, in reverse order */
 
+    NewNumOperands = Index;
     Index--;
     for (i = 0; i < ArgCount; i++)
     {
@@ -927,7 +930,11 @@
      * pop everything off of the operand stack and delete those
      * objects
      */
-    AcpiDsObjStackPopAndDelete (ArgCount, WalkState);
+    WalkState->NumOperands = i;
+    AcpiDsObjStackPopAndDelete (NewNumOperands, WalkState);
+
+    /* Restore operand count */
+    WalkState->NumOperands = PrevNumOperands;
 
     ACPI_EXCEPTION ((AE_INFO, Status, "While creating Arg %u", Index));
     return_ACPI_STATUS (Status);
```
