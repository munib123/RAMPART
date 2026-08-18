# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5280_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5280_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 198-238 of the vulnerable file.

	/*	Make sure we hold a reference count during the destructor call
		otherwise, when the destructor ends the storage might be freed
		when the refcount reaches 0 a second time
	 */
	if (EG(objects_store).object_buckets[handle].valid) {
		if (obj->refcount == 1) {
			if (!EG(objects_store).object_buckets[handle].destructor_called) {
				EG(objects_store).object_buckets[handle].destructor_called = 1;

				if (obj->dtor) {
					if (handlers && !obj->handlers) {
						obj->handlers = handlers;
					}
					zend_try {
						obj->dtor(obj->object, handle TSRMLS_CC);
					} zend_catch {
						failure = 1;
					} zend_end_try();
				}
			}
			
			/* re-read the object from the object store as the store might have been reallocated in the dtor */
			obj = &EG(objects_store).object_buckets[handle].bucket.obj;

			if (obj->refcount == 1) {
				GC_REMOVE_ZOBJ_FROM_BUFFER(obj);
				if (obj->free_storage) {
					zend_try {
						obj->free_storage(obj->object TSRMLS_CC);
					} zend_catch {
						failure = 1;
					} zend_end_try();
				}
				ZEND_OBJECTS_STORE_ADD_TO_FREE_LIST();
			}
		}
	}

	obj->refcount--;

#if ZEND_DEBUG_OBJECTS
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -215,7 +215,7 @@
 					} zend_end_try();
 				}
 			}
-			
+
 			/* re-read the object from the object store as the store might have been reallocated in the dtor */
 			obj = &EG(objects_store).object_buckets[handle].bucket.obj;
 
@@ -306,8 +306,8 @@
 {
 	zend_object_handle handle = Z_OBJ_HANDLE_P(zobject);
 	zend_object_store_bucket *obj_bucket = &EG(objects_store).object_buckets[handle];
-	
-	obj_bucket->bucket.obj.handlers = Z_OBJ_HT_P(zobject);;
+
+	obj_bucket->bucket.obj.handlers = Z_OBJ_HT_P(zobject);
 	obj_bucket->destructor_called = 1;
 }
 
```
