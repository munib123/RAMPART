# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5282_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5282_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 213-253 of the vulnerable file.

/* {{{ wddx_stack_is_empty
 */
static int wddx_stack_is_empty(wddx_stack *stack)
{
	if (stack->top == 0) {
		return 1;
	} else {
		return 0;
	}
}
/* }}} */

/* {{{ wddx_stack_destroy
 */
static int wddx_stack_destroy(wddx_stack *stack)
{
	register int i;

	if (stack->elements) {
		for (i = 0; i < stack->top; i++) {
			if (((st_entry *)stack->elements[i])->data)	{
				zval_ptr_dtor(&((st_entry *)stack->elements[i])->data);
			}
			if (((st_entry *)stack->elements[i])->varname) {
				efree(((st_entry *)stack->elements[i])->varname);
			}
			efree(stack->elements[i]);
		}
		efree(stack->elements);
	}
	return SUCCESS;
}
/* }}} */

/* {{{ release_wddx_packet_rsrc
 */
static void release_wddx_packet_rsrc(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	smart_str *str = (smart_str *)rsrc->ptr;
	smart_str_free(str);
	efree(str);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -230,7 +230,8 @@
 
 	if (stack->elements) {
 		for (i = 0; i < stack->top; i++) {
-			if (((st_entry *)stack->elements[i])->data)	{
+			if (((st_entry *)stack->elements[i])->data
+					&& ((st_entry *)stack->elements[i])->type != ST_FIELD)	{
 				zval_ptr_dtor(&((st_entry *)stack->elements[i])->data);
 			}
 			if (((st_entry *)stack->elements[i])->varname) {
```
