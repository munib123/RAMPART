# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4717_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4717_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 10522-10562 of the vulnerable file.

	ginst = mono_metadata_get_generic_inst (count, type_argv);
	g_free (type_argv);

	tmp_context.class_inst = klass->generic_class ? klass->generic_class->context.class_inst : NULL;
	tmp_context.method_inst = ginst;

	inflated = mono_class_inflate_generic_method (method, &tmp_context);
	imethod = (MonoMethodInflated *) inflated;

	/*FIXME but I think this is no longer necessary*/
	if (method->klass->image->dynamic) {
		MonoDynamicImage *image = (MonoDynamicImage*)method->klass->image;
		/*
		 * This table maps metadata structures representing inflated methods/fields
		 * to the reflection objects representing their generic definitions.
		 */
		mono_loader_lock ();
		mono_g_hash_table_insert (image->generic_def_objects, imethod, rmethod);
		mono_loader_unlock ();
	}
	
	return mono_method_get_object (mono_object_domain (rmethod), inflated, NULL);
}

#ifndef DISABLE_REFLECTION_EMIT

static MonoMethod *
inflate_mono_method (MonoClass *klass, MonoMethod *method, MonoObject *obj)
{
	MonoMethodInflated *imethod;
	MonoGenericContext *context;
	int i;

	/*
	 * With generic code sharing the klass might not be inflated.
	 * This can happen because classes inflated with their own
	 * type arguments are "normalized" to the uninflated class.
	 */
	if (!klass->generic_class)
		return method;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10539,6 +10539,9 @@
 		mono_g_hash_table_insert (image->generic_def_objects, imethod, rmethod);
 		mono_loader_unlock ();
 	}
+
+	if (!mono_verifier_is_method_valid_generic_instantiation (inflated))
+		mono_raise_exception (mono_get_exception_argument ("typeArguments", "Invalid generic arguments"));
 	
 	return mono_method_get_object (mono_object_domain (rmethod), inflated, NULL);
 }
```
