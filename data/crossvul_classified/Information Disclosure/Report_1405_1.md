# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1405_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1405_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 156-196 of the vulnerable file.

 * vips_malloc:
 * @object: (nullable): allocate memory local to this #VipsObject, or %NULL
 * @size: number of bytes to allocate
 *
 * g_malloc() local to @object, that is, the memory will be automatically 
 * freed for you when the object is closed. If @object is %NULL, you need to 
 * free the memory explicitly with g_free().
 *
 * This function cannot fail. See vips_tracked_malloc() if you are 
 * allocating large amounts of memory.
 *
 * See also: vips_tracked_malloc().
 *
 * Returns: (transfer full): a pointer to the allocated memory.
 */
void *
vips_malloc( VipsObject *object, size_t size )
{
	void *buf;

	buf = g_malloc( size );

        if( object ) {
		g_signal_connect( object, "postclose", 
			G_CALLBACK( vips_malloc_cb ), buf );
		object->local_memory += size;
	}

	return( buf );
}

/**
 * vips_strdup:
 * @object: (nullable): allocate memory local to this #VipsObject, or %NULL
 * @str: string to copy
 *
 * g_strdup() a string. When @object is freed, the string will be freed for
 * you.  If @object is %NULL, you need to 
 * free the memory yourself with g_free().
 *
 * This function cannot fail. 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -173,7 +173,7 @@
 {
 	void *buf;
 
-	buf = g_malloc( size );
+	buf = g_malloc0( size );
 
         if( object ) {
 		g_signal_connect( object, "postclose", 
@@ -317,7 +317,7 @@
 	 */
 	size += 16;
 
-        if( !(buf = g_try_malloc( size )) ) {
+        if( !(buf = g_try_malloc0( size )) ) {
 #ifdef DEBUG
 		g_assert_not_reached();
 #endif /*DEBUG*/
```
