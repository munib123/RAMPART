# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3430_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3430_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 701-741 of the vulnerable file.

		return 0;
	
	return this->bounds [dimension].lower_bound;
}

static void
ves_icall_System_Array_ClearInternal (MonoArray *arr, int idx, int length)
{
	int sz = mono_array_element_size (mono_object_class (arr));
	memset (mono_array_addr_with_size (arr, sz, idx), 0, length * sz);
}

static gboolean
ves_icall_System_Array_FastCopy (MonoArray *source, int source_idx, MonoArray* dest, int dest_idx, int length)
{
	int element_size;
	void * dest_addr;
	void * source_addr;
	MonoClass *src_class;
	MonoClass *dest_class;
	int i;

	MONO_ARCH_SAVE_REGS;

	if (source->obj.vtable->klass->rank != dest->obj.vtable->klass->rank)
		return FALSE;

	if (source->bounds || dest->bounds)
		return FALSE;

	/* there's no integer overflow since mono_array_length returns an unsigned integer */
	if ((dest_idx + length > mono_array_length (dest)) ||
		(source_idx + length > mono_array_length (source)))
		return FALSE;

	src_class = source->obj.vtable->klass->element_class;
	dest_class = dest->obj.vtable->klass->element_class;

	/*
	 * Handle common cases.
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -718,7 +718,6 @@
 	void * source_addr;
 	MonoClass *src_class;
 	MonoClass *dest_class;
-	int i;
 
 	MONO_ARCH_SAVE_REGS;
 
@@ -742,6 +741,10 @@
 
 	/* Case1: object[] -> valuetype[] (ArrayList::ToArray) */
 	if (src_class == mono_defaults.object_class && dest_class->valuetype) {
+		// FIXME: This is racy
+		return FALSE;
+		/*
+		  int i;
 		int has_refs = dest_class->has_references;
 		for (i = source_idx; i < source_idx + length; ++i) {
 			MonoObject *elem = mono_array_get (source, MonoObject*, i);
@@ -762,6 +765,7 @@
 				memcpy (addr, (char *)elem + sizeof (MonoObject), element_size);
 		}
 		return TRUE;
+		*/
 	}
 
 	/* Check if we're copying a char[] <==> (u)short[] */
@@ -772,13 +776,18 @@
 		if (mono_class_is_subclass_of (src_class, dest_class, FALSE))
 			;
 		/* Case2: object[] -> reftype[] (ArrayList::ToArray) */
-		else if (mono_class_is_subclass_of (dest_class, src_class, FALSE))
+		else if (mono_class_is_subclass_of (dest_class, src_class, FALSE)) {
+			// FIXME: This is racy
+			return FALSE;
+			/*
+			  int i;
 			for (i = source_idx; i < source_idx + length; ++i) {
 				MonoObject *elem = mono_array_get (source, MonoObject*, i);
 				if (elem && !mono_object_isinst (elem, dest_class))
 					return FALSE;
 			}
-		else
+			*/
+		} else
 			return FALSE;
 	}
 
```
