# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in c
**Pair ID:** 2582_0
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2582_0`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```c
Lines 577-617 of the vulnerable file.

	}

	return (ACPI_CAST_PTR(struct acpi_namespace_node, handle));
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ns_terminate
 *
 * PARAMETERS:  none
 *
 * RETURN:      none
 *
 * DESCRIPTION: free memory allocated for namespace and ACPI table storage.
 *
 ******************************************************************************/

void acpi_ns_terminate(void)
{
	acpi_status status;

	ACPI_FUNCTION_TRACE(ns_terminate);

#ifdef ACPI_EXEC_APP
	{
		union acpi_operand_object *prev;
		union acpi_operand_object *next;

		/* Delete any module-level code blocks */

		next = acpi_gbl_module_code_list;
		while (next) {
			prev = next;
			next = next->method.mutex;
			prev->method.mutex = NULL;	/* Clear the Mutex (cheated) field */
			acpi_ut_remove_reference(prev);
		}
	}
#endif

	/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -594,25 +594,20 @@
 void acpi_ns_terminate(void)
 {
 	acpi_status status;
+	union acpi_operand_object *prev;
+	union acpi_operand_object *next;
 
 	ACPI_FUNCTION_TRACE(ns_terminate);
 
-#ifdef ACPI_EXEC_APP
-	{
-		union acpi_operand_object *prev;
-		union acpi_operand_object *next;
-
-		/* Delete any module-level code blocks */
-
-		next = acpi_gbl_module_code_list;
-		while (next) {
-			prev = next;
-			next = next->method.mutex;
-			prev->method.mutex = NULL;	/* Clear the Mutex (cheated) field */
-			acpi_ut_remove_reference(prev);
-		}
-	}
-#endif
+	/* Delete any module-level code blocks */
+
+	next = acpi_gbl_module_code_list;
+	while (next) {
+		prev = next;
+		next = next->method.mutex;
+		prev->method.mutex = NULL;	/* Clear the Mutex (cheated) field */
+		acpi_ut_remove_reference(prev);
+	}
 
 	/*
 	 * Free the entire namespace -- all nodes and all objects
```
