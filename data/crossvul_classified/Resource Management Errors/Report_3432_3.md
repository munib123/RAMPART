# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3432_3
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3432_3`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 11424-11464 of the vulnerable file.

	SigBuffer buf;

	check_array_for_usertypes (sig->arguments);

	sigbuffer_init (&buf, 32);

	sigbuffer_add_value (&buf, 0x06);
	for (i = 0; i < na; ++i) {
		MonoReflectionType *type = mono_array_get (sig->arguments, MonoReflectionType*, i);
		encode_reflection_type (assembly, type, &buf);
	}

	buflen = buf.p - buf.buf;
	result = mono_array_new (mono_domain_get (), mono_defaults.byte_class, buflen);
	memcpy (mono_array_addr (result, char, 0), buf.buf, buflen);
	sigbuffer_free (&buf);

	return result;
}

void 
mono_reflection_create_dynamic_method (MonoReflectionDynamicMethod *mb)
{
	ReflectionMethodBuilder rmb;
	MonoMethodSignature *sig;
	MonoClass *klass;
	GSList *l;
	int i;

	sig = dynamic_method_to_signature (mb);

	reflection_methodbuilder_from_dynamic_method (&rmb, mb);

	/*
	 * Resolve references.
	 */
	/* 
	 * Every second entry in the refs array is reserved for storing handle_class,
	 * which is needed by the ldtoken implementation in the JIT.
	 */
	rmb.nrefs = mb->nrefs;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11441,14 +11441,55 @@
 	return result;
 }
 
+typedef struct {
+	MonoMethod *handle;
+	MonoDomain *domain;
+} DynamicMethodReleaseData;
+	
+static MonoReferenceQueue *dynamic_method_queue;
+
+void
+mono_reflection_shutdown (void)
+{
+	MonoReferenceQueue *queue;
+	mono_loader_lock ();
+	queue = dynamic_method_queue;
+	dynamic_method_queue = NULL;
+	if (queue)
+		mono_gc_reference_queue_free (queue);
+	mono_loader_unlock ();
+}
+
+static void
+free_dynamic_method (void *dynamic_method)
+{
+	DynamicMethodReleaseData *data = dynamic_method;
+
+	mono_runtime_free_method (data->domain, data->handle);
+	g_free (data);
+}
+
 void 
 mono_reflection_create_dynamic_method (MonoReflectionDynamicMethod *mb)
 {
+	MonoReferenceQueue *queue;
+	MonoMethod *handle;
+	DynamicMethodReleaseData *release_data;
 	ReflectionMethodBuilder rmb;
 	MonoMethodSignature *sig;
 	MonoClass *klass;
 	GSList *l;
 	int i;
+
+	if (mono_runtime_is_shutting_down ())
+		mono_raise_exception (mono_get_exception_invalid_operation (""));
+
+	if (!(queue = dynamic_method_queue)) {
+		mono_loader_lock ();
+		if (!(queue = dynamic_method_queue))
+			queue = dynamic_method_queue = mono_gc_reference_queue_new (free_dynamic_method);
+		mono_loader_unlock ();
+	}
 
 	sig = dynamic_method_to_signature (mb);
 
@@ -11507,7 +11548,12 @@
 
 	klass = mb->owner ? mono_class_from_mono_type (mono_reflection_type_get_handle ((MonoReflectionType*)mb->owner)) : mono_defaults.object_class;
 
-	mb->mhandle = reflection_methodbuilder_to_mono_method (klass, &rmb, sig);
+	mb->mhandle = handle = reflection_methodbuilder_to_mono_method (klass, &rmb, sig);
+	release_data = g_new (DynamicMethodReleaseData, 1);
+	release_data->handle = handle;
+	release_data->domain = mono_object_get_domain ((MonoObject*)mb);
+	if (!mono_gc_reference_queue_add (queue, (MonoObject*)mb, release_data))
+		g_free (release_data);
 
 	/* Fix up refs entries pointing at us */
 	for (l = mb->referenced_by; l; l = l->next) {
@@ -11532,16 +11578,6 @@
 }
 
 #endif /* DISABLE_REFLECTION_EMIT */
-
-void
-mono_reflection_destroy_dynamic_method (MonoReflectionDynamicMethod *mb)
-{
-	g_assert (mb);
-
-	if (mb->mhandle)
-		mono_runtime_free_method (
-			mono_object_get_domain ((MonoObject*)mb), mb->mhandle);
-}
 
 /**
  * 
```
