# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3429_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3429_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 837-880 of the vulnerable file.

	if (MONO_TYPE_IS_REFERENCE (&ec->byval_arg)) {
		g_assert (esize == sizeof (gpointer));
		mono_gc_wbarrier_generic_store (ea, *(gpointer*)value);
	} else {
		g_assert (ec->inited);
		if (ec->has_references)
			mono_gc_wbarrier_value_copy (ea, value, 1, ec);
		memcpy (ea, value, esize);
	}
}

static void
ves_icall_System_Runtime_CompilerServices_RuntimeHelpers_InitializeArray (MonoArray *array, MonoClassField *field_handle)
{
	MonoClass *klass = array->obj.vtable->klass;
	guint32 size = mono_array_element_size (klass);
	MonoType *type = mono_type_get_underlying_type (&klass->element_class->byval_arg);
	int align;
	const char *field_data;

	if (MONO_TYPE_IS_REFERENCE (type) ||
			(type->type == MONO_TYPE_VALUETYPE &&
				(!mono_type_get_class (type) ||
				mono_type_get_class (type)->has_references))) {
		MonoException *exc = mono_get_exception_argument("array",
			"Cannot initialize array containing references");
		mono_raise_exception (exc);
	}

	if (!(field_handle->type->attrs & FIELD_ATTRIBUTE_HAS_FIELD_RVA)) {
		MonoException *exc = mono_get_exception_argument("field_handle",
			"Field doesn't have an RVA");
		mono_raise_exception (exc);
	}

	size *= array->max_length;
	field_data = mono_field_get_data (field_handle);

	if (size > mono_type_size (field_handle->type, &align)) {
		MonoException *exc = mono_get_exception_argument("field_handle",
			"Field not large enough to fill array");
		mono_raise_exception (exc);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -854,12 +854,9 @@
 	int align;
 	const char *field_data;
 
-	if (MONO_TYPE_IS_REFERENCE (type) ||
-			(type->type == MONO_TYPE_VALUETYPE &&
-				(!mono_type_get_class (type) ||
-				mono_type_get_class (type)->has_references))) {
+	if (MONO_TYPE_IS_REFERENCE (type) || type->type == MONO_TYPE_VALUETYPE) {
 		MonoException *exc = mono_get_exception_argument("array",
-			"Cannot initialize array containing references");
+			"Cannot initialize array of non-primitive type.");
 		mono_raise_exception (exc);
 	}
 
```
